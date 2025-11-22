importScripts('https://www.gstatic.com/firebasejs/8.3.2/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/8.3.2/firebase-messaging.js');

firebase.initializeApp({
    apiKey: "AIzaSyDKoHGpy71rk0EeGTuyUmXiNF734X2tARU",
    authDomain: "siame-adfe1.firebaseapp.com",
    projectId: "siame-adfe1",
    storageBucket: "siame-adfe1.firebasestorage.app",
    messagingSenderId: "926015535595",
    appId: "1:926015535595:web:c010edc5630b93cd3441ae",
    measurementId: ""
});

const messaging = firebase.messaging();
messaging.setBackgroundMessageHandler(function (payload) {
    return self.registration.showNotification(payload.data.title, {
        body: payload.data.body ? payload.data.body : '',
        icon: payload.data.icon ? payload.data.icon : ''
    });
});