# kotlinx.serialization keeps its generated serializers via companion objects.
-keepclassmembers class **$$serializer { *; }
-keepclasseswithmembers class ** {
    public static ** Companion;
}
-dontwarn kotlinx.serialization.**
