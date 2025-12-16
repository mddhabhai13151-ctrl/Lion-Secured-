const functions = require('firebase-functions');
const admin = require('firebase-admin');
const crypto = require('crypto');
admin.initializeApp();
const db = admin.firestore();

exports.sendFcmCommand = functions.https.onCall(async (data, context) => {
  const { tokens, cmd } = data;
  if(!tokens || !cmd) throw new functions.https.HttpsError('invalid-argument','tokens & cmd required');
  const ts = Date.now().toString();
  const hmacKey = functions.config().lion?.hmac_key || 'dev_secret';
  const sig = crypto.createHmac('sha256', hmacKey).update(`${cmd}|${ts}`).digest('base64');
  const payload = { data: { cmd, ts, sig } };
  const res = await admin.messaging().sendToDevice(tokens, payload);
  return { success: true, res };
});

exports.createHideSession = functions.https.onCall(async (data, context) => {
  const email = data.email;
  if(!email) throw new functions.https.HttpsError('invalid-argument','email required');
  const sessionId = crypto.randomBytes(20).toString('hex');
  const expiresAt = Date.now() + 10*24*3600*1000;
  await db.collection('hide_sessions').doc(sessionId).set({ email, expiresAt, createdAt: admin.firestore.FieldValue.serverTimestamp() });
  return { sessionId };
});

exports.storeEphemeralKey = functions.https.onCall(async (data, context) => {
  const { sessionId, ephemeralKeyBase64 } = data;
  if(!sessionId || !ephemeralKeyBase64) throw new functions.https.HttpsError('invalid-argument','missing');
  await db.collection('hide_sessions').doc(sessionId).update({ ephemeralKeyBase64, storedAt: admin.firestore.FieldValue.serverTimestamp() });
  return { ok: true };
});

exports.retrieveEphemeralKey = functions.https.onCall(async (data, context) => {
  const { sessionId } = data;
  if(!sessionId) throw new functions.https.HttpsError('invalid-argument','missing');
  const doc = await db.collection('hide_sessions').doc(sessionId).get();
  if(!doc.exists) throw new functions.https.HttpsError('not-found','session not found');
  const d = doc.data();
  if(!d.ephemeralKeyBase64) throw new functions.https.HttpsError('failed-precondition','no key stored');
  return { ephemeralKeyBase64: d.ephemeralKeyBase64 };
});
