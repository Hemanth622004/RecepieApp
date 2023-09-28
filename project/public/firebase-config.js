// firebase-config.js
import { getFirestore } from './firebase-admin/firestore';
import admin from './firebase-admin';

const serviceAccount = require("./key.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

export const db = getFirestore(admin);
