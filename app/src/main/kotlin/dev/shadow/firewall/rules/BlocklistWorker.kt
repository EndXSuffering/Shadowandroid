package dev.shadow.firewall.rules

import android.content.Context
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dev.shadow.firewall.FirewallApp
import java.util.concurrent.TimeUnit

/**
 * Keeps the subscribed lists current in the background.
 *
 * WorkManager rather than a timer inside the VPN service, because the lists should keep
 * updating whether or not the tunnel happens to be running, and should survive a reboot.
 */
class BlocklistWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {

    override suspend fun doWork(): Result {
        val app = applicationContext as? FirewallApp ?: return Result.failure()
        return try {
            val succeeded = app.blocklistRepository.refresh()
            // A failed download is almost always a transient network problem, so let
            // WorkManager back off and try again rather than waiting a whole cycle.
            if (succeeded) Result.success() else Result.retry()
        } catch (error: Exception) {
            Log.w(TAG, "blocklist refresh failed", error)
            if (runAttemptCount < MAX_ATTEMPTS) Result.retry() else Result.failure()
        }
    }

    companion object {
        private const val TAG = "BlocklistWorker"
        private const val WORK_NAME = "blocklist-refresh"
        private const val MAX_ATTEMPTS = 3

        /**
         * Installs or replaces the periodic refresh. Called at startup and whenever the
         * frequency or metering preference changes.
         */
        fun schedule(context: Context, frequency: UpdateFrequency, unmeteredOnly: Boolean) {
            val manager = WorkManager.getInstance(context)
            if (!frequency.isAutomatic) {
                manager.cancelUniqueWork(WORK_NAME)
                return
            }

            val constraints = Constraints.Builder()
                .setRequiredNetworkType(
                    if (unmeteredOnly) NetworkType.UNMETERED else NetworkType.CONNECTED,
                )
                .build()

            val request = PeriodicWorkRequestBuilder<BlocklistWorker>(
                frequency.hours, TimeUnit.HOURS,
            )
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
                .build()

            manager.enqueueUniquePeriodicWork(
                WORK_NAME,
                // UPDATE keeps the existing schedule's next-run time when nothing material
                // changed, so toggling a setting does not reset the clock every time.
                ExistingPeriodicWorkPolicy.UPDATE,
                request,
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }
    }
}
