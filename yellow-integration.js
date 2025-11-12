// yellow-integration.js - COMPLETE FIXED VERSION WITH PROPER SIGNATURES

import {
  createAppSessionMessage,
  createAuthRequestMessage,
  createAuthVerifyMessage,
  createCloseAppSessionMessage,
  createEIP712AuthMessageSigner,
  parseAnyRPCResponse,
  RPCMethod,
} from '@erc7824/nitrolite';
import { createWalletClient, custom, keccak256, toHex, getAddress } from 'viem';
import { generatePrivateKey, privateKeyToAccount, sign } from 'viem/accounts';
import { base } from 'viem/chains';

// ========== Configuration ==========
const CLEARNODE_WS = 'wss://clearnet.yellow.com/ws';
const MERCHANT = '0xb765c6a3677378b5107acb8a350e7e91e8f0cb37';
const APP_NAME = 'Zombie Game';
const AUTH_SCOPE = 'http://localhost:8000/';
const SESSION_DURATION = 3600;

// Storage keys
const SESSION_KEY_STORAGE = 'zombie_game_session_key';
const JWT_STORAGE = 'zombie_game_jwt';
const ACTIVE_SESSIONS_STORAGE = 'zombie_game_active_sessions';

// ========== Global State ==========
let ws = null;
let walletClient = null;
let userAddress = null;
let sessionKey = null;
let isAuthenticated = false;
let isAuthAttempted = false;
let jwtToken = null;
let pendingAuthParams = null;
let activeSessions = {}; // Track active app sessions

// ✅ Global constant for timestamp
const EXPIRE_TIMESTAMP = String(Math.floor(Date.now() / 1000) + SESSION_DURATION);

// Add this helper at top of file (global)
async function waitForAuth(maxSeconds = 30) {
  let waited = 0;
  while (!isAuthenticated && waited < maxSeconds * 2) {
    await new Promise(resolve => setTimeout(resolve, 500));
    waited++;
  }
  if (!isAuthenticated) throw new Error('Authentication timeout - not authenticated');
}

// ========== Session Key Functions ==========
function generateSessionKey() {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  return { 
    privateKey: privateKey, 
    address: account.address 
  };
}

function getStoredSessionKey() {
  try {
    const stored = localStorage.getItem(SESSION_KEY_STORAGE);
    if (!stored) return null;
    const parsed = JSON.parse(stored);
    if (!parsed.privateKey || !parsed.address) return null;
    return parsed;
  } catch {
    return null;
  }
}

function storeSessionKey(key) {
  try {
    localStorage.setItem(SESSION_KEY_STORAGE, JSON.stringify(key));
    console.log('💾 Session key stored');
  } catch (e) {
    console.warn('Failed to store session key:', e);
  }
}

function removeSessionKey() {
  try {
    localStorage.removeItem(SESSION_KEY_STORAGE);
    console.log('🗑️ Session key removed');
  } catch (e) {
    console.warn('Failed to remove session key:', e);
  }
}

// ========== JWT Functions ==========
function getStoredJWT() {
  try {
    return localStorage.getItem(JWT_STORAGE);
  } catch {
    return null;
  }
}

function storeJWT(token) {
  try {
    localStorage.setItem(JWT_STORAGE, token);
    console.log('💾 JWT stored');
  } catch (e) {
    console.warn('Failed to store JWT:', e);
  }
}

function removeJWT() {
  try {
    localStorage.removeItem(JWT_STORAGE);
    console.log('🗑️ JWT removed');
  } catch (e) {
    console.warn('Failed to remove JWT:', e);
  }
}

// ========== Active Sessions Management ==========
function getActiveSessions() {
  try {
    const stored = localStorage.getItem(ACTIVE_SESSIONS_STORAGE);
    return stored ? JSON.parse(stored) : {};
  } catch {
    return {};
  }
}

function storeActiveSessions(sessions) {
  try {
    localStorage.setItem(ACTIVE_SESSIONS_STORAGE, JSON.stringify(sessions));
    console.log('💾 Active sessions stored:', Object.keys(sessions).length);
  } catch (e) {
    console.warn('Failed to store sessions:', e);
  }
}

function addActiveSession(gunName, appSessionId, usdcAmount) {
  activeSessions[gunName] = {
    appSessionId,
    usdcAmount,
    createdAt: Date.now(),
    status: 'open'
  };
  storeActiveSessions(activeSessions);
  console.log('✅ Session added:', gunName, appSessionId);
}

function removeActiveSession(gunName) {
  if (activeSessions[gunName]) {
    delete activeSessions[gunName];
    storeActiveSessions(activeSessions);
    console.log('🗑️ Session removed:', gunName);
  }
}

function getActiveSession(gunName) {
  return activeSessions[gunName] || null;
}

// ========== Clear Authentication State ==========
function clearAuthState() {
  console.log('🧹 Clearing authentication state...');
  removeJWT();
  removeSessionKey();
  isAuthenticated = false;
  isAuthAttempted = false;
  jwtToken = null;
  pendingAuthParams = null;
}

// ========== Get Wallet Client ==========
async function getWalletClient() {
  if (!window.ethereum) {
    throw new Error('No wallet found - please install MetaMask');
  }

  const accounts = await window.ethereum.request({ 
    method: 'eth_requestAccounts' 
  });
  
  const address = accounts?.[0];
  if (!address) {
    throw new Error('No account found in wallet');
  }

  // Switch to Base network
  try {
    await window.ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: '0x2105' }],
    });
    console.log('✅ Switched to Base');
  } catch (err) {
    console.warn('⚠️ Network switch warning:', err.message);
  }

  const checksummedAddress = getAddress(address);
  const client = createWalletClient({
    account: checksummedAddress,
    chain: base,
    transport: custom(window.ethereum),
  });

  return { 
    client: client, 
    address: checksummedAddress 
  };
}

// ========== WebSocket Functions ==========
function openClearnodeWS() {
  return new Promise((resolve, reject) => {
    if (ws?.readyState === WebSocket.OPEN) {
      console.log('✅ WebSocket already open');
      return resolve(ws);
    }

    if (ws) {
      console.log('🔌 Closing existing WebSocket...');
      try {
        ws.close();
      } catch (e) {
        console.warn('Error closing WebSocket:', e);
      }
      ws = null;
    }

    console.log('🔌 Opening WebSocket...');
    ws = new WebSocket(CLEARNODE_WS);

    ws.onopen = () => {
      console.log('✅ WebSocket connected!');
      resolve(ws);
    };

    ws.onerror = (err) => {
      console.error('❌ WebSocket error:', err);
      reject(new Error('WebSocket connection failed'));
    };

    ws.onmessage = (evt) => {
      handleWebSocketMessage(evt.data);
    };

    ws.onclose = () => {
      console.log('🔌 WebSocket closed');
      isAuthenticated = false;
      isAuthAttempted = false;
      pendingAuthParams = null;
    };
  });
}

// ========== EIP-712 Domain ==========
function getAuthDomain() {
  return {
    name: APP_NAME,
  };
}

// ========== Handle WebSocket Messages ==========
async function handleWebSocketMessage(data) {
  console.log('📨 Raw Message:', data);
  
  try {
    const response = parseAnyRPCResponse(data);
    console.log('📩 Parsed Response:', response);

    // Handle authentication challenge
    if (response.method === RPCMethod.AuthChallenge) {
      console.log('🔐 Auth challenge received');
      const challengeMessage = response.params?.challengeMessage || response.params?.challenge_message;
      
      if (!walletClient || !sessionKey || !userAddress) {
        console.error('❌ Missing auth requirements');
        return;
      }

      if (!pendingAuthParams) {
        console.error('❌ No pending auth params');
        return;
      }

      console.log('✍️ Signing auth challenge...');
      const eip712Signer = createEIP712AuthMessageSigner(
        walletClient,
        pendingAuthParams,
        getAuthDomain()
      );

      try {
        const authVerifyPayload = await createAuthVerifyMessage(
          eip712Signer, 
          response
        );
        
        console.log('📤 Sending auth verify...');
        ws.send(authVerifyPayload);
        
      } catch (error) {
        console.error('❌ Signature error:', error);
        clearAuthState();
        window.unityInstance?.SendMessage(
          'ShopManager', 
          'OnPurchaseError', 
          'Signature rejected'
        );
      }
    }

    // Handle authentication success
    if (response.method === RPCMethod.AuthVerify) {
      if (response.params?.success === true) {  // Explicit boolean check
        console.log('✅ AUTHENTICATION SUCCESS!');
        isAuthenticated = true;
        isAuthAttempted = true;  // Prevent re-auth loops
        
        if (response.params.jwtToken) {  // Case-sensitive: jwtToken (matches your send)
          jwtToken = response.params.jwtToken;
          storeJWT(jwtToken);
          console.log('🎫 JWT stored');
        }

        pendingAuthParams = null;
        
        // Load existing sessions
        activeSessions = getActiveSessions();
        
        window.unityInstance?.SendMessage(
          'Web3Manager', 
          'OnYellowConnected', 
          'Authenticated'
        );
      } else {
        console.error('❌ Auth verification failed:', response.params?.error || 'Unknown');
        clearAuthState();
        isAuthAttempted = false;  // Allow retry
        window.unityInstance?.SendMessage(
          'ShopManager', 
          'OnPurchaseError', 
          'Auth failed - retrying...'
        );
      }
    }

    // Handle errors
    if (response.method === RPCMethod.Error) {
      console.error('❌ RPC Error:', response.params);
      
      const errorMsg = response.params?.error || 'Unknown error';
      if (errorMsg.toLowerCase().includes('authentication')) {
        console.log('🔄 Authentication error detected - session expired');
        isAuthenticated = false;
        clearAuthState();
        
        // If transfer is in progress, notify it of the auth error
        if (window.transferErrorCallback) {
          window.transferErrorCallback('Session expired - please try again');
        }
        
        // Don't send error to Unity - let the purchase function handle retry
        return;
      }
      
      // For non-auth errors, notify transfer if in progress
      if (window.transferErrorCallback) {
        window.transferErrorCallback(errorMsg);
        return;
      }
      
      // Otherwise send to Unity
      window.unityInstance?.SendMessage(
        'ShopManager', 
        'OnPurchaseError', 
        `RPC Error: ${errorMsg}`
      );
    }

    // Handle create_app_session response
    // Handle transfer response
    if (response.method === 'transfer') {
      console.log('✅ Transfer completed!');
      console.log('   Response:', JSON.stringify(response.params, null, 2));
      
      if (window.transferCallback) {
        window.transferCallback(response.params);
      }
    }

    // Handle create_app_session response
    if (response.method === 'create_app_session') {
      console.log('✅ App session created!');
      const appSessionId = response.params?.app_session_id;
      
      if (appSessionId && window.purchaseCallback) {
        window.purchaseCallback(appSessionId);
      }
    }

    // Handle close_app_session response
    if (response.method === 'close_app_session') {
      console.log('✅ App session closed!');
      const appSessionId = response.params?.app_session_id;
      
      if (appSessionId && window.closeCallback) {
        window.closeCallback(appSessionId);
      }
    }

  } catch (error) {
    console.error('❌ Error handling message:', error);
  }
}

// ========== Initialize Yellow Network ==========
window.InitializeYellow = async function () {
  try {
    console.log('🟡 Initializing Yellow Network...');

    // Get or create session key
    sessionKey = getStoredSessionKey();
    if (!sessionKey) {
      console.log('🔑 Generating NEW session key');
      sessionKey = generateSessionKey();
      storeSessionKey(sessionKey);
    } else {
      console.log('🔑 Using EXISTING session key');
    }
    console.log('Session Key Address:', sessionKey.address);

    // Get wallet client
    const { client, address } = await getWalletClient();
    walletClient = client;
    userAddress = address;
    console.log('👤 User Address:', userAddress);

    // Open WebSocket
    await openClearnodeWS();

    // Load existing sessions
    activeSessions = getActiveSessions();
    console.log('📂 Loaded', Object.keys(activeSessions).length, 'active sessions');

    // Check for existing JWT - but verify it's for the current session key
    const storedJWT = getStoredJWT();
    if (storedJWT) {
      // Parse JWT to check if it matches current session key
      try {
        const jwtPayload = JSON.parse(atob(storedJWT.split('.')[1]));
        const jwtSessionKey = jwtPayload.policy?.participant;
        
        console.log('🎫 Found existing JWT');
        console.log('   JWT session key:', jwtSessionKey);
        console.log('   Current session key:', sessionKey.address);
        
        if (jwtSessionKey && jwtSessionKey.toLowerCase() === sessionKey.address.toLowerCase()) {
          console.log('✅ JWT matches current session key - using it');
          jwtToken = storedJWT;
          isAuthenticated = true;
          return true;
        } else {
          console.warn('⚠️ JWT is for different session key - clearing it');
          removeJWT();
        }
      } catch (e) {
        console.warn('⚠️ Failed to parse JWT - clearing it');
        removeJWT();
      }
    }

    // Start authentication
    if (!isAuthAttempted) {
      console.log('🔐 Starting authentication...');
      isAuthAttempted = true;

      console.log('⏰ Expire timestamp:', EXPIRE_TIMESTAMP);

      // ✅ CRITICAL FIX per EIP-712 Policy type:
      // - application: MUST be ADDRESS type (use MERCHANT address)
      // - participant: session key address (the key being authorized)
      // - app_name in auth_request: application name string
      pendingAuthParams = {
        scope: AUTH_SCOPE,
        application: MERCHANT,  // ✅ MERCHANT address (EIP-712 Policy requires address type!)
        participant: sessionKey.address,  // Session key being authorized
        expire: EXPIRE_TIMESTAMP,
        allowances: [],
      };

      const authRequestParams = {
        address: userAddress,
        session_key: sessionKey.address,
        app_name: APP_NAME,  // Application name ("Zombie Game")
        expire: EXPIRE_TIMESTAMP,
        scope: AUTH_SCOPE,
        application: MERCHANT,  // ✅ MERCHANT address (application identifier)
        allowances: [],
      };

      console.log('📤 Sending auth_request...');
      const authRequestPayload = await createAuthRequestMessage(authRequestParams);
      ws.send(authRequestPayload);
      
      console.log('⏳ Waiting for auth_challenge...');
    }

    console.log('✅ Yellow initialized! Waiting for authentication...');
    return true;

  } catch (error) {
    console.error('❌ Initialization failed:', error);
    isAuthAttempted = false;
    pendingAuthParams = null;
    
    window.unityInstance?.SendMessage(
      'ShopManager', 
      'OnPurchaseError', 
      String(error?.message || 'Initialization failed')
    );
    
    return false;
  }
};

// ========== Create Message Signer (USER WALLET - FOR APP SESSIONS) ==========
async function createUserWalletSigner() {
  if (!walletClient || !userAddress) {
    throw new Error('Wallet not ready');
  }

  return async (payload) => {
    console.log('✍️ Signing with USER WALLET (not session key)');
    const message = JSON.stringify(payload);
    const messageBytes = toHex(message);
    const digestHex = keccak256(messageBytes);
    
    const signature = await walletClient.signMessage({
      account: userAddress,
      message: { raw: digestHex },
    });
    
    console.log('✅ User wallet signature obtained');
    return signature;
  };
}

// ========== Transfer USDC to Merchant ==========
async function transferToMerchant(gunName, usdcAmount) {
  await waitForAuth();

  if (!isAuthenticated) {
    throw new Error('Not authenticated');
  }

  // ✅ Get and validate JWT matches current session key
  // Use global jwtToken if available, otherwise get from storage
  const currentJWT = jwtToken || getStoredJWT();
  if (!currentJWT) {
    throw new Error('No JWT token available');
  }

  try {
    const jwtParts = currentJWT.split('.');
    const payload = JSON.parse(atob(jwtParts[1]));
    const jwtSessionKey = payload?.policy?.participant?.toLowerCase();
    
    if (jwtSessionKey !== sessionKey.address.toLowerCase()) {
      console.error('❌ JWT session key mismatch!');
      console.error('   JWT session key:', jwtSessionKey);
      console.error('   Current session key:', sessionKey.address);
      console.error('   Clearing stale JWT and re-authenticating...');
      clearAuthState();
      isAuthenticated = false;
      throw new Error('Session expired - please try again');
    }
    console.log('✅ JWT validated for current session key');
  } catch (e) {
    if (e.message === 'Session expired - please try again') {
      throw e;
    }
    console.error('❌ JWT validation failed:', e);
    clearAuthState();
    isAuthenticated = false;
    throw new Error('Invalid JWT - please try again');
  }

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.log('🔌 Reconnecting WebSocket...');
    await openClearnodeWS();
  }

  console.log('💰 Transferring USDC to merchant');
  console.log('   From:', userAddress);
  console.log('   To:', MERCHANT);
  console.log('   Amount:', usdcAmount, 'USDC');
  console.log('   Gun:', gunName);

  // ✅ CRITICAL: Sign the transfer request with SESSION KEY (authorized by JWT)
  const requestId = Date.now();
  const timestamp = Date.now();
  
  // ✅ Yellow Network uses DECIMAL STRING amounts, not micro-units!
  // Server balance: "1" = 1 USDC, "0.1" = 0.1 USDC
  const amountStr = parseFloat(usdcAmount).toString();
  console.log('💰 Amount format:');
  console.log('   Display:', usdcAmount, 'USDC');
  console.log('   API format:', amountStr, '(decimal string)');
  
  const req = [requestId, 'transfer', {
    destination: MERCHANT,  // ✅ Recipient wallet address
    allocations: [{  // ✅ REQUIRED: Array of assets to transfer
      asset: 'usdc',
      amount: amountStr  // ✅ Decimal string (e.g., "0.1")
    }]
  }, timestamp];
  
  console.log('📤 Creating transfer request...');
  console.log('   Request:', JSON.stringify(req, null, 2));
  
  // ✅ Sign with session key (local private key - NOT MetaMask!)
  const sessionKeyAccount = privateKeyToAccount(sessionKey.privateKey);
  const message = JSON.stringify(req);
  const messageHash = keccak256(toHex(message));
  
  console.log('✍️ Signing transfer with SESSION KEY (local)...');
  console.log('   Session key address:', sessionKey.address);
  console.log('   Message:', message);
  console.log('   Message hash:', messageHash);
  
  // ✅ Sign the hash directly (NO Ethereum prefix - raw ECDSA signature)
  const signatureObj = await sign({
    hash: messageHash,
    privateKey: sessionKey.privateKey
  });
  
  // ✅ Convert signature {r, s, v} to compact hex string format: 0x + r + s + v
  const vHex = Number(signatureObj.v).toString(16).padStart(2, '0');
  const signature = signatureObj.r + signatureObj.s.substring(2) + vHex;
  
  console.log('✅ Session key signature obtained');
  console.log('   Signature:', signature);
  
  // ✅ Send transfer request (connection is already authenticated via JWT)
  const transferRequest = {
    req: req,
    sig: [signature]
    // Note: JWT not needed in request body - connection is authenticated
  };

  console.log('📤 Sending signed transfer request...');
  console.log('   Has signature:', !!signature);
  console.log('   Session authenticated:', isAuthenticated);
  console.log('   Request:', JSON.stringify(transferRequest, null, 2));
  
  ws.send(JSON.stringify(transferRequest));
  
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      console.error('❌ Transfer timeout after 10 seconds');
      console.error('   No response from server - possible issues:');
      console.error('   1. Signature format incorrect');
      console.error('   2. Amount format incorrect');
      console.error('   3. Insufficient balance');
      console.error('   4. Server error');
      delete window.transferCallback;
      delete window.transferErrorCallback;
      reject(new Error('Transfer timeout'));
    }, 10000);

    window.transferCallback = (result) => {
      clearTimeout(timeout);
      console.log('✅ Transfer complete:', result);
      delete window.transferCallback;
      delete window.transferErrorCallback;
      resolve(result);
    };

    // Handle auth errors during transfer
    window.transferErrorCallback = (error) => {
      clearTimeout(timeout);
      console.error('❌ Transfer failed:', error);
      delete window.transferCallback;
      delete window.transferErrorCallback;
      reject(new Error(error));
    };
  });
}

// ========== Create Purchase Session (DEPRECATED - using transfer instead) ==========
async function createPurchaseSession_OLD(gunName, usdcAmount) {
  await waitForAuth();

  if (!isAuthenticated) {
    throw new Error('Not authenticated');
  }

  if (!walletClient || !userAddress) {
    throw new Error('Wallet not ready');
  }

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.log('🔌 Reconnecting WebSocket...');
    await openClearnodeWS();
  }

  const buyer = userAddress;
  console.log('💰 Creating purchase session (OLD METHOD)');
  console.log('   Buyer:', buyer);
  console.log('   Merchant:', MERCHANT);
  console.log('   Amount:', usdcAmount, 'USDC');

  // ✅ CRITICAL FIX: Use USER WALLET signer, not session key!
  // According to docs: "The create app session request must be signed by all participants with non-zero allocations"
  const userWalletSigner = await createUserWalletSigner();

  // ✅ FIXED: Single participant (buyer only) - merchant signs automatically
  // Yellow Network virtual ledger allows single-party app sessions
  const definition = {
    application: 'clearnode',
    protocol: 'NitroRPC/0.2',
    participants: [buyer],  // ✅ Only buyer - merchant handled by server
    weights: [100],  // ✅ Single weight for single participant
    quorum: 100,
    challenge: 86400,
    nonce: Date.now(),
  };

  // USDC with 6 decimals
  const usdcAmountWithDecimals = String(Math.floor(Number(usdcAmount) * 1_000_000));

  // ✅ Single participant allocations - buyer pays from unified ledger to merchant
  const allocations = [
    { participant: buyer, asset: 'usdc', amount: usdcAmountWithDecimals },
  ];

  console.log('✍️ Creating app session message...');
  console.log('   Definition:', JSON.stringify(definition, null, 2));
  console.log('   Allocations:', JSON.stringify(allocations, null, 2));
  
  // ✅ CRITICAL: createAppSessionMessage expects an ARRAY of channel states
  const channelStates = [{
    definition: definition,
    allocations: allocations
  }];
  
  console.log('   Channel states (array):', JSON.stringify(channelStates, null, 2));
  
  // ✅ FIX: Declare signedMessage BEFORE the try block
  let signedMessage;
  
  try {
    console.log('🔐 Signing with USER WALLET (buyer has non-zero allocation)...');
    signedMessage = await createAppSessionMessage(
      userWalletSigner,  // ✅ Using user wallet, not session key!
      channelStates  // ✅ Pass as ARRAY
    );
    
    console.log('✅ Message created successfully');
    console.log('   Message preview:', signedMessage.substring(0, 200) + '...');
  } catch (msgError) {
    console.error('❌ Error creating message:', msgError);
    console.error('   Error details:', msgError.message);
    console.error('   Stack:', msgError.stack);
    throw msgError;
  }

  console.log('📤 Sending create_app_session...');
  console.log('   Message length:', signedMessage.length, 'bytes');
  
  // ========== SIGNATURE STRUCTURE ANALYSIS ==========
  try {
    const msgObj = JSON.parse(signedMessage);
    console.log('   🔍 Message Structure Analysis:');
    console.log('      req:', msgObj.req ? 'present' : 'missing');
    console.log('      sig:', msgObj.sig ? 'present' : 'missing');
    console.log('      sig length:', msgObj.sig?.length);
    
    if (msgObj.sig && Array.isArray(msgObj.sig)) {
      console.log('      Signatures in array:');
      msgObj.sig.forEach((sig, idx) => {
        console.log(`         [${idx}]: ${sig.substring(0, 20)}...${sig.substring(sig.length - 10)} (${sig.length} chars)`);
      });
      console.log('      ⚠️ Server expects signatures from ALL participants!');
      console.log('         Participants:', JSON.stringify(definition.participants));
      console.log('         Signatures provided:', msgObj.sig.length);
      console.log('         Expected signatures:', definition.participants.length);
    }
    
    // Preview the full message
    const msgPreview = signedMessage.length > 500 ? 
      signedMessage.substring(0, 500) + '...' : 
      signedMessage;
    console.log('   Message content:', msgPreview);
  } catch (e) {
    console.log('   (Could not analyze message structure)');
  }

  // ✅ CRITICAL INSIGHT: After authentication, the WebSocket connection itself is authenticated
  // JWT authenticated the WebSocket - we DON'T need to attach JWT to individual requests!
  // The server already knows this connection is authenticated
  
  console.log('📡 Sending via authenticated WebSocket connection');
  console.log('   (JWT not needed - WebSocket is already authenticated)');
  
  ws.send(signedMessage);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Session creation timeout'));
    }, 30000);

    window.purchaseCallback = (appSessionId) => {
      clearTimeout(timeout);
      console.log('✅ Session created:', appSessionId);
      
      // Store active session
      addActiveSession(gunName, appSessionId, usdcAmount);
      
      resolve({ app_session_id: appSessionId });
      delete window.purchaseCallback;
    };
  });
}

// ========== Close Purchase Session ==========
async function closePurchaseSession(gunName) {
  await waitForAuth(); // NEW: Block until authenticated

  if (!isAuthenticated) {
    throw new Error('Not authenticated');
  }

  const session = getActiveSession(gunName);
  if (!session) {
    throw new Error('No active session found for ' + gunName);
  }

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.log('🔌 Reconnecting WebSocket...');
    await openClearnodeWS();
  }

  console.log('🔒 Closing app session');
  console.log('   Gun:', gunName);
  console.log('   Session ID:', session.appSessionId);

  const buyer = userAddress;
  const usdcAmountWithDecimals = String(Math.floor(Number(session.usdcAmount) * 1_000_000));

  // ✅ Use USER WALLET signer for closing too
  const userWalletSigner = await createUserWalletSigner();

  // Return all funds to merchant (game completed)
  const allocations = [
    { participant: buyer, asset: 'usdc', amount: '0' },
    { participant: MERCHANT, asset: 'usdc', amount: usdcAmountWithDecimals },
  ];

  const sessionData = JSON.stringify({
    gunName: gunName,
    gameCompleted: true,
    closedAt: new Date().toISOString()
  });

  console.log('✍️ Creating close session message...');
  console.log('   Allocations:', JSON.stringify(allocations, null, 2));
  console.log('   Session Data:', sessionData);
  
  console.log('🔐 Signing close message with USER WALLET...');
  const signedMessage = await createCloseAppSessionMessage(
    userWalletSigner,  // ✅ Using user wallet
    {
      app_session_id: session.appSessionId,
      allocations: allocations,
      session_data: sessionData
    }
  );

  // ✅ WebSocket is already authenticated - no need to attach JWT
  console.log('📤 Sending close_app_session...');
  console.log('   (via authenticated WebSocket connection)');
  ws.send(signedMessage);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Session close timeout'));
    }, 30000);

    window.closeCallback = (appSessionId) => {
      clearTimeout(timeout);
      console.log('✅ Session closed:', appSessionId);
      
      // Remove from active sessions
      removeActiveSession(gunName);
      
      resolve({ app_session_id: appSessionId, status: 'closed' });
      delete window.closeCallback;
    };
  });
}

// ========== Purchase Gun ==========
window.PurchaseGunWithUSDC = async function (gunName, usdcAmount) {
  try {
    console.log('🔫 Purchase Request:', gunName, usdcAmount, 'USDC');

    // Check if already have active session for this gun
    const existingSession = getActiveSession(gunName);
    if (existingSession) {
      console.log('⚠️ Already have active session for', gunName);
      console.log('   Closing existing session first...');
      
      try {
        await closePurchaseSession(gunName);
      } catch (closeError) {
        console.warn('⚠️ Failed to close existing session:', closeError);
        // Continue anyway - might be stale
        removeActiveSession(gunName);
      }
    }

    if (!isAuthenticated) {
      console.log('⚠️ Not authenticated, initializing...');
      
      const initialized = await window.InitializeYellow();
      if (!initialized) {
        throw new Error('Failed to initialize');
      }
      
      console.log('⏳ Waiting for authentication...');
      window.unityInstance?.SendMessage(
        'ShopManager', 
        'OnPaymentProcessing', 
        'Authenticating...'
      );
      
      await new Promise((resolve, reject) => {
        let checks = 0;
        const maxChecks = 60;
        
        const checkAuth = setInterval(() => {
          checks++;
          
          if (isAuthenticated) {
            clearInterval(checkAuth);
            console.log('✅ Authenticated!');
            resolve(true);
          } else if (checks >= maxChecks) {
            clearInterval(checkAuth);
            reject(new Error('Authentication timeout'));
          }
        }, 500);
      });
    }

    console.log('💳 Processing payment via transfer...');
    window.unityInstance?.SendMessage(
      'ShopManager', 
      'OnPaymentProcessing', 
      'Transferring USDC...'
    );

    // ✅ Try transfer - if session expired, re-authenticate and retry once
    let response;
    try {
      response = await transferToMerchant(gunName, String(usdcAmount));
    } catch (transferError) {
      if (transferError.message === 'Session expired - please try again') {
        console.log('🔄 Session expired, re-authenticating...');
        
        // Re-authenticate
        const reInitialized = await window.InitializeYellow();
        if (!reInitialized) {
          throw new Error('Failed to re-authenticate');
        }
        
        console.log('⏳ Waiting for re-authentication...');
        window.unityInstance?.SendMessage(
          'ShopManager', 
          'OnPaymentProcessing', 
          'Re-authenticating...'
        );
        
        await new Promise((resolve, reject) => {
          let checks = 0;
          const maxChecks = 60;
          
          const checkAuth = setInterval(() => {
            checks++;
            
            if (isAuthenticated) {
              clearInterval(checkAuth);
              console.log('✅ Re-authenticated! Retrying transfer...');
              resolve(true);
            } else if (checks >= maxChecks) {
              clearInterval(checkAuth);
              reject(new Error('Re-authentication timeout'));
            }
          }, 500);
        });
        
        // Retry transfer
        console.log('🔄 Retrying transfer...');
        window.unityInstance?.SendMessage(
          'ShopManager', 
          'OnPaymentProcessing', 
          'Transferring USDC...'
        );
        response = await transferToMerchant(gunName, String(usdcAmount));
      } else {
        throw transferError;
      }
    }

    console.log('✅ Purchase successful!');
    console.log('   Gun:', gunName);
    console.log('   Transfer result:', response);
    
    window.unityInstance?.SendMessage('ShopManager', 'OnPurchaseSuccess', gunName);
    
    return true;
    
  } catch (error) {
    console.error('❌ Purchase failed:', error);
    
    window.unityInstance?.SendMessage(
      'ShopManager', 
      'OnPurchaseError', 
      String(error?.message || 'Purchase failed')
    );
    
    return false;
  }
};

// ========== Close Gun Session ==========
window.CloseGunSession = async function (gunName) {
  try {
    console.log('🔒 Close Gun Session Request:', gunName);

    if (!isAuthenticated) {
      throw new Error('Not authenticated');
    }

    const session = getActiveSession(gunName);
    if (!session) {
      console.log('ℹ️ No active session for', gunName);
      return true;
    }

    console.log('🔒 Closing session...');
    const response = await closePurchaseSession(gunName);

    console.log('✅ Session closed successfully!');
    console.log('   Gun:', gunName);
    console.log('   Session ID:', response.app_session_id);
    
    window.unityInstance?.SendMessage(
      'ShopManager', 
      'OnSessionClosed', 
      gunName
    );
    
    return true;
    
  } catch (error) {
    console.error('❌ Close session failed:', error);
    
    window.unityInstance?.SendMessage(
      'ShopManager', 
      'OnSessionCloseError', 
      String(error?.message || 'Close failed')
    );
    
    return false;
  }
};

// ========== Get Active Sessions ==========
window.GetActiveSessions = function () {
  return Object.keys(activeSessions);
};

// ========== Close All Sessions ==========
window.CloseAllSessions = async function () {
  try {
    console.log('🔒 Closing all active sessions...');
    
    const sessionNames = Object.keys(activeSessions);
    console.log('   Found', sessionNames.length, 'active sessions');
    
    for (const gunName of sessionNames) {
      try {
        console.log('   Closing session:', gunName);
        await closePurchaseSession(gunName);
      } catch (error) {
        console.warn('   Failed to close', gunName, ':', error.message);
        // Remove from storage anyway
        removeActiveSession(gunName);
      }
    }
    
    console.log('✅ All sessions closed');
    return true;
    
  } catch (error) {
    console.error('❌ Error closing sessions:', error);
    return false;
  }
};

// ========== Close Yellow Network ==========
window.CloseYellowSession = async function () {
  try {
    console.log('🔒 Closing Yellow Network session...');
    
    // Close all active app sessions first
    await window.CloseAllSessions();
    
    if (ws) {
      ws.close();
      ws = null;
    }
    
    clearAuthState();
    walletClient = null;
    userAddress = null;
    sessionKey = null;
    activeSessions = {};
    
    console.log('✅ Yellow Network session closed');
  } catch (error) {
    console.error('❌ Error closing session:', error);
  }
};

// ========== Page Cleanup ==========
window.addEventListener('beforeunload', () => {
  console.log('🔄 Page unloading - cleaning up...');
  try {
    if (ws) {
      ws.close();
    }
  } catch (error) {
    console.warn('Cleanup error:', error);
  }
});

// ========== Helper Functions ==========
window.IsYellowAuthenticated = function () {
  return isAuthenticated;
};

window.GetYellowBalance = function () {
  return null;
};

window.HasActiveSession = function (gunName) {
  return !!getActiveSession(gunName);
};

// ========== Initialization Message ==========
console.log('🟡 Yellow Integration - SIGNATURE FIX loaded! 🚀');
console.log('📚 Functions: InitializeYellow, PurchaseGunWithUSDC, CloseGunSession, CloseAllSessions');
console.log('🔑 Using USER WALLET signatures for app sessions (not session key)');
