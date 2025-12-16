1. Open in Android Studio.
2. Add firebase google-services.json to app/ if using FCM.
3. Configure cloud functions: cd cloud_functions && npm install && firebase deploy --only functions
4. Generate Android keystore and configure signing.
5. Build & test on device.
