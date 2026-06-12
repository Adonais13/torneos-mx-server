import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import admin from 'firebase-admin';
import { ethers } from 'ethers';
import crypto from 'crypto';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Cargar variables de entorno
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Inicializar Firebase Admin
// Render ejecuta el comando de inicio desde el directorio del repositorio
const serviceAccount = JSON.parse(
  readFileSync('./serviceAccountKey.json', 'utf8')
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();

app.use(cors({ origin: true }));
app.use(express.json());

// ABI mínimo para interactuar con contratos ERC-20
const ERC20_ABI = [
  "event Transfer(address indexed from, address indexed to, uint256 value)",
  "function balanceOf(address account) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)"
];

// Helper para desencriptar llaves (AES-256-GCM)
function decrypt(text) {
  const [ivHex, encryptedHex, authTagHex] = text.split(':');
  if (!ivHex || !encryptedHex || !authTagHex) {
    throw new Error('Formato de clave encriptada inválido.');
  }

  const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const encryptedText = Buffer.from(encryptedHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Helper para encriptar llaves (AES-256-GCM)
function encrypt(text) {
  const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${encrypted}:${authTag}`;
}

// Middleware para validar el token de Firebase del usuario
async function authenticateUser(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No autorizado. Se requiere token Bearer.' });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Error al verificar token:', error);
    return res.status(401).json({ error: 'Token inválido o expirado.' });
  }
}

// 1. POST /api/getOrCreateWallet
app.post('/api/getOrCreateWallet', authenticateUser, async (req, res) => {
  const uid = req.user.uid;
  const userRef = db.collection('usuarios').doc(uid);

  try {
    const result = await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        return { error: 'El documento del usuario no existe.', status: 404 };
      }

      const userData = userDoc.data();
      if (userData.wallet_address) {
        return { walletAddress: userData.wallet_address };
      }

      const wallet = ethers.Wallet.createRandom();
      const encryptedKey = encrypt(wallet.privateKey);

      transaction.update(userRef, {
        wallet_address: wallet.address,
        encrypted_private_key: encryptedKey
      });

      return { walletAddress: wallet.address };
    });

    if (result.error) {
      return res.status(result.status).json({ error: result.error });
    }
    return res.json(result);
  } catch (error) {
    console.error('Error en getOrCreateWallet:', error);
    return res.status(500).json({ error: error.message });
  }
});

// 2. POST /api/verifyDeposit
app.post('/api/verifyDeposit', authenticateUser, async (req, res) => {
  const uid = req.user.uid;
  const { transactionHash } = req.body || {};

  if (!transactionHash || !/^0x([A-Fa-f0-9]{64})$/.test(transactionHash)) {
    return res.status(400).json({ error: 'Hash de transacción inválido.' });
  }

  try {
    const txRef = db.collection('transacciones').doc(transactionHash);
    const txDoc = await txRef.get();
    if (txDoc.exists) {
      return res.status(400).json({ error: 'Esta transacción ya ha sido procesada previamente.' });
    }

    const userRef = db.collection('usuarios').doc(uid);
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'Usuario no registrado.' });
    }

    const userWalletAddress = userDoc.data().wallet_address;
    if (!userWalletAddress) {
      return res.status(400).json({ error: 'El usuario no tiene una wallet de depósito configurada.' });
    }

    let amountTransferred = 0n;
    let recipientMatched = false;

    // Conectar a la blockchain de Base
    const provider = new ethers.JsonRpcProvider(process.env.POLYGON_RPC_URL);
    const receipt = await provider.getTransactionReceipt(transactionHash);

    if (!receipt) {
      return res.status(404).json({ error: 'No se encontró la transacción en la blockchain. Asegúrate de que se haya minado.' });
    }

    if (receipt.status !== 1) {
      return res.status(400).json({ error: 'La transacción de la blockchain falló (revertida).' });
    }

    const iface = new ethers.Interface(ERC20_ABI);
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() === process.env.USDC_CONTRACT_ADDRESS.toLowerCase()) {
        try {
          const parsedLog = iface.parseLog(log);
          if (parsedLog && parsedLog.name === 'Transfer') {
            const toAddress = parsedLog.args.to;
            if (toAddress.toLowerCase() === userWalletAddress.toLowerCase()) {
              amountTransferred = parsedLog.args.value;
              recipientMatched = true;
              break;
            }
          }
        } catch (e) {
          // Ignorar logs no compatibles
        }
      }
    }

    if (!recipientMatched) {
      return res.status(400).json({ error: 'No se encontró transferencia de USDT válida hacia la billetera del usuario en esta transacción.' });
    }

    const creditsToDeposit = Number(ethers.formatUnits(amountTransferred, 6));

    await db.runTransaction(async (transaction) => {
      const innerTxDoc = await transaction.get(txRef);
      if (innerTxDoc.exists) {
        throw new Error('La transacción fue procesada en paralelo.');
      }

      transaction.set(txRef, {
        userId: uid,
        tipo: 'deposito',
        monto: creditsToDeposit,
        token: 'USDT',
        txHash: transactionHash,
        fecha: admin.firestore.FieldValue.serverTimestamp(),
        estado: 'completed'
      });

      transaction.update(userRef, {
        balance_creditos: admin.firestore.FieldValue.increment(creditsToDeposit)
      });
    });

    return res.json({ success: true, amount: creditsToDeposit });
  } catch (error) {
    console.error('Error en verifyDeposit:', error);
    return res.status(500).json({ error: error.message });
  }
});

// 3. POST /api/processWithdrawal
app.post('/api/processWithdrawal', authenticateUser, async (req, res) => {
  const uid = req.user.uid;
  const { amount, destinationAddress } = req.body || {};

  if (!amount || typeof amount !== 'number' || amount <= 0) {
    return res.status(400).json({ error: 'Monto de retiro inválido.' });
  }

  if (!destinationAddress || !ethers.isAddress(destinationAddress)) {
    return res.status(400).json({ error: 'Dirección de destino de Base inválida.' });
  }

  const userRef = db.collection('usuarios').doc(uid);
  const txId = db.collection('transacciones').doc().id;

  try {
    const { encryptedPrivateKey, userWalletAddress } = await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) {
        throw new Error('Usuario no registrado.');
      }

      const userData = userDoc.data();
      const currentBalance = userData.balance_creditos || 0;

      if (currentBalance < amount) {
        throw new Error('Saldo insuficiente para procesar el retiro.');
      }

      if (!userData.wallet_address || !userData.encrypted_private_key) {
        throw new Error('El usuario no tiene una billetera Web3 inicializada.');
      }

      transaction.update(userRef, {
        balance_creditos: admin.firestore.FieldValue.increment(-amount)
      });

      transaction.set(db.collection('transacciones').doc(txId), {
        userId: uid,
        tipo: 'retiro',
        monto: amount,
        token: 'USDT',
        destino: destinationAddress,
        fecha: admin.firestore.FieldValue.serverTimestamp(),
        estado: 'pending'
      });

      return {
        encryptedPrivateKey: userData.encrypted_private_key,
        userWalletAddress: userData.wallet_address
      };
    });

    let finalTxHash = '';
    const decryptedKey = decrypt(encryptedPrivateKey);
    const provider = new ethers.JsonRpcProvider(process.env.POLYGON_RPC_URL);
    const userWallet = new ethers.Wallet(decryptedKey, provider);

    const amountUnits = ethers.parseUnits(amount.toString(), 6);
    const usdcContractUser = new ethers.Contract(process.env.USDC_CONTRACT_ADDRESS, ERC20_ABI, userWallet);
    const rawUserUSDC = await usdcContractUser.balanceOf(userWalletAddress);

    if (rawUserUSDC >= amountUnits) {
      const userGasBalance = await provider.getBalance(userWalletAddress);
      const minGas = ethers.parseEther("0.0005");

      if (userGasBalance < minGas) {
        if (!process.env.MASTER_PRIVATE_KEY) {
          throw new Error('Clave maestra ausente: Imposible patrocinar gas.');
        }
        const masterWallet = new ethers.Wallet(process.env.MASTER_PRIVATE_KEY, provider);
        const needed = minGas - userGasBalance;

        const masterGasBalance = await provider.getBalance(masterWallet.address);
        if (masterGasBalance < needed) {
          throw new Error('La billetera maestra carece de ETH en Base.');
        }

        const sponsorTx = await masterWallet.sendTransaction({
          to: userWalletAddress,
          value: needed
        });
        await sponsorTx.wait(1);
      }

      const tx = await usdcContractUser.transfer(destinationAddress, amountUnits);
      const receipt = await tx.wait(1);
      finalTxHash = receipt.hash;
    } else {
      if (!process.env.MASTER_PRIVATE_KEY) {
        throw new Error('Saldo insuficiente y MASTER_PRIVATE_KEY ausente.');
      }
      const masterWallet = new ethers.Wallet(process.env.MASTER_PRIVATE_KEY, provider);
      const usdcContractMaster = new ethers.Contract(process.env.USDC_CONTRACT_ADDRESS, ERC20_ABI, masterWallet);

      const rawMasterUSDC = await usdcContractMaster.balanceOf(masterWallet.address);
      if (rawMasterUSDC < amountUnits) {
        throw new Error('Saldo de USDT insuficiente en la billetera maestra.');
      }

      const tx = await usdcContractMaster.transfer(destinationAddress, amountUnits);
      const receipt = await tx.wait(1);
      finalTxHash = receipt.hash;
    }

    await db.collection('transacciones').doc(txId).update({
      estado: 'completed',
      txHash: finalTxHash
    });

    return res.json({ success: true, txHash: finalTxHash });
  } catch (error) {
    console.error('Error en processWithdrawal:', error);
    try {
      await db.runTransaction(async (transaction) => {
        transaction.update(userRef, {
          balance_creditos: admin.firestore.FieldValue.increment(amount)
        });
        transaction.update(db.collection('transacciones').doc(txId), {
          estado: 'failed',
          error: error.message
        });
      });
    } catch (rollbackError) {
      console.error('Error crítico en rollback:', rollbackError);
    }
    return res.status(500).json({ error: error.message });
  }
});

// Arrancar el puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor API Web3 gratis corriendo en el puerto ${PORT}`);
});
