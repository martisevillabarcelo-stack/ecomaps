/**********************
 * USUARIO Y ESTADO
 **********************/
let usuario = null;
let co2Total = 0;
let contadorResiduos = 0;
let rachaDiaria = 0;
let ultimaFechaReciclaje = null;
let historialActividad = [];
let logrosDesbloqueados = [];
let materialesStats = { plastico: 0, papel: 0, vidrio: 0, organico: 0, total: 0 };
let centroEducativo = "";
let ubicacionUsuario = { lat: null, lng: null, direccion: "" };
// Sesión criptográfica (clave derivada de la contraseña en memoria)
let sessionCryptoKey = null;
let sessionSalt = null; // base64
// Constante de aplicación para cifrar el nombre de usuario localmente.
// Nota: para producción, NO embedas secretos en el cliente.
const APP_SECRET = "EcoMapsLocalSecret_v1";

// --- Helpers WebCrypto ---
function bufToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuf(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function deriveBits(password, salt, iterations = 120000, length = 256) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
    baseKey,
    length
  );
  return bits;
}

async function hashPassword(password, saltBuf) {
  const bits = await deriveBits(password, saltBuf, 120000, 256);
  return bufToBase64(bits);
}

async function importAesKeyFromSecret(secret) {
  const enc = new TextEncoder();
  const salt = new TextEncoder().encode('eco_username_salt');
  const derived = await deriveBits(secret, salt, 60000, 256);
  return crypto.subtle.importKey('raw', derived, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptTextAESGCM(plain) {
  const key = await importAesKeyFromSecret(APP_SECRET);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plain));
  return bufToBase64(iv) + ':' + bufToBase64(ct);
}

async function decryptTextAESGCM(payload) {
  try {
    const [ivB64, ctB64] = payload.split(':');
    const iv = new Uint8Array(base64ToBuf(ivB64));
    const ct = base64ToBuf(ctB64);
    const key = await importAesKeyFromSecret(APP_SECRET);
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(dec);
  } catch (e) {
    console.warn('Error descifrando texto:', e);
    return null;
  }
}

/**********************
 * BASE DE DATOS LOCAL
 **********************/
const residuos = {
  "botella": { contenedor: "Contenedor amarillo", co2: 0.08 },
  "lata": { contenedor: "Contenedor amarillo", co2: 0.13 },
  "papel": { contenedor: "Contenedor azul", co2: 0.02 },
  "cartón": { contenedor: "Contenedor azul", co2: 0.05 },
  "botella de vidrio": { contenedor: "Contenedor verde", co2: 0.25 },
  "pila": { contenedor: "Contenedor de pilas", co2: 0.4 },
  "móvil": { contenedor: "Punto limpio", co2: 1.2 }
};

/**********************
 * LOGIN / REGISTRO
 **********************/
async function loginUsuario() {
  try {
    const nombre = document.getElementById("nombreUsuario").value.trim();
    const password = document.getElementById("passwordUsuario").value.trim();
    const centroSeleccionado = document.getElementById("centroEducativo").value;

    console.debug('loginUsuario invoked', { nombre, centroSeleccionado });

    if (!nombre || !password) {
      alert("Introduce usuario y contraseña");
      return;
    }

    const clave = "eco_user_" + nombre;
    let datos = JSON.parse(localStorage.getItem(clave));

    if (datos) {
      console.debug('Cuenta encontrada en localStorage', clave, datos);
    // Cuenta legacy: contraseña en texto plano -> migrar a hash
      if (datos.password) {
        console.debug('Cuenta legacy con contraseña en texto plano, migrando...');
        if (datos.password !== password) {
          alert("Contraseña incorrecta");
          return;
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const passwordHash = await hashPassword(password, salt);
        datos.passwordHash = passwordHash;
        datos.salt = bufToBase64(salt);
        delete datos.password;
        localStorage.setItem(clave, JSON.stringify(datos));
        console.debug('Migración completada para', clave);
      } else if (datos.passwordHash && datos.salt) {
        const saltBuf = base64ToBuf(datos.salt);
        const hash = await hashPassword(password, saltBuf);
        if (hash !== datos.passwordHash) {
          console.debug('Hash mismatch', { provided: hash, stored: datos.passwordHash });
          alert("Contraseña incorrecta");
          return;
        }
      } else {
        console.debug('Formato de cuenta inesperado', datos);
        alert("Formato de cuenta desconocido. Regístrate de nuevo.");
        return;
      }

      if (centroSeleccionado && !datos.centro) {
        datos.centro = centroSeleccionado;
        localStorage.setItem(clave, JSON.stringify(datos));
      }
  } else {
    // Registro: guardamos salt + hash y ciframos el nombre dentro del objeto
      if (!centroSeleccionado) {
        alert("Por favor, selecciona tu centro educativo");
        return;
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const passwordHash = await hashPassword(password, salt);
      const nombreEnc = await encryptTextAESGCM(nombre);
      datos = { passwordHash, salt: bufToBase64(salt), username_enc: nombreEnc, co2: 0, residuos: 0, codigosUsados: [], centro: centroSeleccionado };
      localStorage.setItem(clave, JSON.stringify(datos));
  }

  usuario = nombre;
  centroEducativo = datos.centro || "";
  localStorage.setItem("eco_ultimo_usuario", usuario);
  cargarUsuario();

  document.getElementById("loginPantalla").style.display = "none";
  actualizarRanking();
  actualizarRankingCentros();
  actualizarEstadisticasGlobales();
  obtenerUbicacion();
    console.debug('Login successful for', usuario);
  } catch (e) {
    console.error('loginUsuario error:', e);
    alert('Error al iniciar sesión: ' + (e && e.message ? e.message : 'ver consola'));
  }
}

/**********************
 * CARGAR / GUARDAR
 **********************/
// Muestra una curiosidad en la pantalla de inicio y en el perfil.
function mostrarCuriosidadInicio() {
  // Si ya existe un array global `curiosidades` (definido en index.html), lo usamos.
  const pool = (typeof curiosidades !== 'undefined' && Array.isArray(curiosidades) && curiosidades.length) ? curiosidades : [
    "Reciclar una lata de aluminio ahorra energía suficiente para usar una TV durante 3 horas.",
    "El vidrio puede reciclarse infinitamente sin perder calidad.",
    "Reciclar papel reduce la deforestación y ahorra agua.",
    "El plástico reciclado puede convertirse en ropa o muebles.",
    "Reciclar 1 kg de papel ahorra más de 1 kg de CO₂."
  ];

  const indice = Math.floor(Math.random() * pool.length);
  const texto = pool[indice];

  const elInicio = document.getElementById('curiosidad-inicio');
  if (elInicio) elInicio.textContent = texto;

  const elPerfil = document.getElementById('curiosidad');
  if (elPerfil) elPerfil.textContent = texto;
}

function cargarUsuario() {
  const datos = JSON.parse(localStorage.getItem("eco_user_" + usuario));
  if (!datos) return;

  co2Total = datos.co2 || 0;
  contadorResiduos = datos.residuos || 0;
  codigosUsados = datos.codigosUsados || [];
  centroEducativo = datos.centro || "";

  document.getElementById("puntuacion").innerText = co2Total.toFixed(2);
  document.getElementById("contador").innerText = contadorResiduos;

  rachaDiaria = datos.racha || 0;
  ultimaFechaReciclaje = datos.ultimaFecha || null;
  historialActividad = datos.historial || [];
  logrosDesbloqueados = datos.logros || [];
  materialesStats = datos.materiales || { plastico: 0, papel: 0, vidrio: 0, organico: 0, total: 0 };

  verificarRacha();
  actualizarRecompensas();
  actualizarNivel();
  actualizarHistorialUI();
  actualizarLogrosUI();
  actualizarEstadisticasExtendidas();
  actualizarEstadisticasGlobales();
  actualizarRankingCentros();

  // Nuevas funciones
  actualizarPerfil();
  actualizarRetos();
  actualizarProgresoRecompensas();
  actualizarNivelMini();
  actualizarRachaStats();
  mostrarCuriosidadInicio();
}

function guardarUsuario() {
  if (!usuario) return;

  const clave = "eco_user_" + usuario;
  const datosAlmacenados = JSON.parse(localStorage.getItem(clave)) || {};

  // Guardamos passwordHash y salt (si existen) en lugar de contraseña en texto plano
  localStorage.setItem(clave, JSON.stringify({
    passwordHash: datosAlmacenados.passwordHash || "",
    salt: datosAlmacenados.salt || "",
    username_enc: datosAlmacenados.username_enc || "",
    co2: co2Total,
    residuos: contadorResiduos,
    codigosUsados: codigosUsados,
    racha: rachaDiaria,
    ultimaFecha: ultimaFechaReciclaje,
    historial: historialActividad,
    logros: logrosDesbloqueados,
    materiales: materialesStats,
    centro: centroEducativo || datosAlmacenados.centro || ""
  }));
}

/**********************
 * BUSCADOR (NORMAL + IA LOCAL)
 **********************/
function buscarResiduo() {
  if (!usuario) {
    alert("Inicia sesión primero");
    return;
  }

  const input = document.getElementById("residuo").value.toLowerCase().trim();
  const resultado = document.getElementById("resultado");

  if (!input) {
    resultado.innerText = "Escribe un residuo";
    return;
  }

  // 🔹 1. Búsqueda directa
  if (residuos[input]) {
    aplicarResultado(residuos[input], input);
    return;
  }

  // 🔹 2. MOTOR IA MEJORADO (Procesamiento de Lenguaje)

  // Limpieza: quitamos artículos y palabras vacías
  const stopWords = ["el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "con", "para", "de", "en"];
  let palabras = input.split(/\s+/).filter(p => !stopWords.includes(p));

  // Normalización básica de plurales (quitamos 's' o 'es' al final)
  palabras = palabras.map(p => {
    if (p.endsWith("es") && p.length > 4) return p.slice(0, -2);
    if (p.endsWith("s") && p.length > 3) return p.slice(0, -1);
    return p;
  });

  const motorIA = {
    reglas: [
      { material: "plastico", keywords: ["plastico", "botella", "envase", "bolsa", "tapa", "yogur", "brick", "lata", "aluminio", "envoltorio", "film", "bandeja", "corcho", "porexpan", "brik", "leche", "zumo"], contenedor: "Contenedor amarillo", co2: 0.08 },
      { material: "papel", keywords: ["papel", "carton", "caja", "revista", "periodico", "folio", "sobre", "folleto", "huevera", "libreta", "libro"], contenedor: "Contenedor azul", co2: 0.05 },
      { material: "vidrio", keywords: ["vidrio", "cristal", "tarro", "frasco", "vino", "cerveza", "perfume", "copa", "vaso"], contenedor: "Contenedor verde", co2: 0.25 },
      { material: "organico", keywords: ["comida", "fruta", "verdura", "cascara", "hueso", "pelo", "poso", "te", "infusion", "pan", "servilleta", "comida", "manzana", "platano", "sobra"], contenedor: "Contenedor orgánico", co2: 0.03 },
      { material: "electronico", keywords: ["movil", "ordenador", "tablet", "cable", "cargador", "pila", "bateria", "pantalla", "raton", "auricular", "tele"], contenedor: "Punto limpio", co2: 1.0 },
      { material: "aceite", keywords: ["aceite", "grasa", "cocina"], contenedor: "Punto limpio / Contenedor aceite", co2: 0.5 },
      { material: "medicamento", keywords: ["pastilla", "medicina", "jarabe", "blister", "prospecto", "aspirina", "paracetamol"], contenedor: "Punto SIGRE (Farmacias)", co2: 0.15 },
      { material: "ropa", keywords: ["ropa", "pantalon", "camiseta", "zapato", "textil", "abrigo", "bota", "calcetin", "prenda"], contenedor: "Contenedor ropa / Punto limpio", co2: 1.5 }
    ]
  };

  let mejorMatch = null;
  let maxPuntuacion = 0;

  // Analizamos cada palabra limpia contra nuestras reglas
  motorIA.reglas.forEach(regla => {
    let puntuacion = 0;
    palabras.forEach(palabra => {
      regla.keywords.forEach(kw => {
        if (palabra.includes(kw) || kw.includes(palabra)) {
          puntuacion += Math.max(palabra.length, kw.length);
        }
      });
    });

    if (puntuacion > maxPuntuacion) {
      maxPuntuacion = puntuacion;
      mejorMatch = regla;
    }
  });

  if (mejorMatch) {
    // Si la puntuación es baja, avisamos que es una suposición
    const confianza = Math.min(Math.floor((maxPuntuacion / 5) * 100), 99);
    aplicarResultadoInformativo(mejorMatch, `IA (Confianza: ${confianza}%)`);
  } else {
    // Fallback: Si no sabe qué es, normalmente va al gris (Resto)
    aplicarResultadoInformativo(
      { contenedor: "Contenedor Gris (Resto)", co2: 0.01 },
      "IA (Por exclusión: No identificado como Reciclable específico)"
    );
  }
}

/**********************
 * APLICAR RESULTADO (SOLO INFO)
 **********************/
function aplicarResultadoInformativo(dato, etiqueta) {
  const resultado = document.getElementById("resultado");
  resultado.innerHTML = `
    🗑️ <b>${dato.contenedor}</b><br>
    🌱 CO₂ que ahorrarías: ${dato.co2.toFixed(2)} kg<br>
    🤖 Detectado: ${etiqueta}<br>
    <small><i>Escanea el código para sumar puntos</i></small>
  `;
}

// Aplica resultado cuando la búsqueda es una entrada directa de la base `residuos`
function aplicarResultado(dato, clave) {
  const resultado = document.getElementById("resultado");
  const nombre = clave || "Residuo";
  resultado.innerHTML = `
    🗑️ <b>${dato.contenedor}</b><br>
    📘 Tipo: ${nombre}<br>
    🌱 CO₂ que ahorrarías: ${dato.co2.toFixed(2)} kg<br>
    <small><i>Escanea el código para sumar puntos</i></small>
  `;
}

/**********************
 * ESCÁNER DE CÓDIGOS DE BARRAS
 **********************/
let html5QrCode = null;
let codigosUsados = [];
let barcodeStream = null;
let barcodeVideo = null;
let barcodeCanvas = null;
let barcodeInterval = null;
let barcodeDetector = null;

// Base de datos de ejemplo de códigos de barras
const productosDB = {
  // --- PLÁSTICO (Amarillo) ---
  "8412345678901": { nombre: "Botella Agua 500ml", categoria: "plastico", co2: 0.15 },
  "8410002000301": { nombre: "Lata de Refresco", categoria: "plastico", co2: 0.20 },
  "8430004000501": { nombre: "Yogur Pack x4", categoria: "plastico", co2: 0.12 },
  "8410123000602": { nombre: "Bote de Champú", categoria: "plastico", co2: 0.25 },
  "8410456000703": { nombre: "Detergente Líquido", categoria: "plastico", co2: 0.40 },
  "8410789000804": { nombre: "Bolsa de Patatas", categoria: "plastico", co2: 0.08 },
  "8410011000905": { nombre: "Tarrina de Helado", categoria: "plastico", co2: 0.18 },
  "8410022001002": { nombre: "Botella de Aceite", categoria: "plastico", co2: 0.22 },

  // --- PAPEL Y CARTÓN (Azul) ---
  "8420003000401": { nombre: "Caja de Galletas", categoria: "papel", co2: 0.10 },
  "8420111001104": { nombre: "Caja de Cereales", categoria: "papel", co2: 0.15 },
  "8420222001205": { nombre: "Periódico Diario", categoria: "papel", co2: 0.05 },
  "8420333001306": { nombre: "Revista Semanal", categoria: "papel", co2: 0.07 },
  "8420444001407": { nombre: "Huevera Cartón", categoria: "papel", co2: 0.09 },
  "8420555001508": { nombre: "Caja de Pizza", categoria: "papel", co2: 0.12 },
  "8420666001609": { nombre: "Sobre de Papel", categoria: "papel", co2: 0.02 },
  "8420777001700": { nombre: "Cuaderno Viejo", categoria: "papel", co2: 0.20 },

  // --- VIDRIO (Verde) ---
  "8430111001801": { nombre: "Botella Vino", categoria: "vidrio", co2: 0.45 },
  "8430222001902": { nombre: "Tarro de Mermelada", categoria: "vidrio", co2: 0.30 },
  "8430333002003": { nombre: "Botella Cerveza", categoria: "vidrio", co2: 0.35 },
  "8430444002104": { nombre: "Frasco Perfume", categoria: "vidrio", co2: 0.25 },
  "8430555002205": { nombre: "Bote de Conservas", categoria: "vidrio", co2: 0.28 },
  "8430666002306": { nombre: "Botella Refresco Vidrio", categoria: "vidrio", co2: 0.40 },

  // --- ORGÁNICO / OTROS ---
  "7501055300075": { nombre: "Envase Biodegradable", categoria: "organico", co2: 0.30 },
  "8440111002404": { nombre: "Restos Comida", categoria: "organico", co2: 0.05 },
  "8440222002505": { nombre: "Cáscaras de Huevo", categoria: "organico", co2: 0.03 },
  "8450111002602": { nombre: "Pilas AA", categoria: "electronico", co2: 0.80 },
  "8450222002703": { nombre: "Móvil Antiguo", categoria: "electronico", co2: 2.50 },
  "8450333002804": { nombre: "Bombilla LED", categoria: "electronico", co2: 0.60 },
  "8440333002906": { nombre: "Cápsula Café", categoria: "plastico", co2: 0.05 },
  "8440444003007": { nombre: "Papel Aluminio", categoria: "plastico", co2: 0.10 }
};

function toggleEscaneo() {
  const container = document.getElementById("reader-container");
  const btn = document.getElementById("btn-escanear");

  if (!usuario) {
    alert("Inicia sesión primero");
    return;
  }

  if (html5QrCode && html5QrCode.isScanning) {
    detenerEscaneo();
  } else {
    container.classList.remove("seccion-oculta");
    btn.innerHTML = '<i class="fa-solid fa-stop"></i> Detener Cámara';
    iniciarEscaneo();
  }
}

function iniciarEscaneo() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showCameraError("Tu navegador no soporta el acceso a la cámara.");
    return;
  }

  // Si existe API nativa de detección de códigos (BarcodeDetector), la usamos como prioridad
  if (window.BarcodeDetector) {
    const supportedFormats = ["ean_13", "ean_8", "upc_a", "code_128", "qr_code"];
    try {
      barcodeDetector = new BarcodeDetector({ formats: supportedFormats });
      startBarcodeDetector();
      return;
    } catch (err) {
      console.warn('BarcodeDetector no pudo inicializarse:', err);
      // si falla, continuamos con Html5Qrcode
    }
  }

  html5QrCode = new Html5Qrcode("reader");
  const config = { fps: 10, qrbox: { width: 250, height: 150 } };

  // Si la librería soporta formatos, intentamos incluir barras comunes
  if (window.Html5QrcodeSupportedFormats) {
    const f = window.Html5QrcodeSupportedFormats;
    const formatoPreferidos = [];
    if (f.EAN_13) formatoPreferidos.push(f.EAN_13);
    if (f.CODE_128) formatoPreferidos.push(f.CODE_128);
    if (f.UPC_A) formatoPreferidos.push(f.UPC_A);
    if (f.QR_CODE) formatoPreferidos.push(f.QR_CODE);
    if (formatoPreferidos.length) config.formatsToSupport = formatoPreferidos;
  }

  // Helper para iniciar con un deviceId o con facingMode
  function startWithCamera(camera) {
    const cameraArg = camera && camera.id ? camera.id : { facingMode: "environment" };
    setCameraStatus("Iniciando cámara...");
    html5QrCode.start(
      cameraArg,
      config,
      (decodedText) => {
        console.log("Decoded:", decodedText);
        setCameraStatus("Código detectado: " + decodedText);
        procesarCodigoDeBarras(decodedText);
      },
      (errorMessage) => {
        // mostramos errores leves en consola para debug
        console.debug("Frame scan error:", errorMessage);
      }
    ).then(() => {
      clearCameraError();
      setCameraStatus("Cámara activa: esperando código...");
    }).catch(err => {
      console.error("Error al iniciar cámara:", err);
      showCameraError("No se pudo acceder a la cámara. Comprueba permisos o dispositivo.");
    });
  }

  // Intentar elegir una cámara física si la librería lo permite
  if (Html5Qrcode.getCameras) {
    Html5Qrcode.getCameras().then(cameras => {
      if (cameras && cameras.length) {
        // Preferimos cámaras traseras (labels con back/rear) o la última disponible
        let preferida = cameras.find(c => /back|rear|trasera|trasero/i.test(c.label)) || cameras[cameras.length - 1];
        startWithCamera(preferida);
      } else {
        startWithCamera(null);
      }
    }).catch(err => {
      console.warn('No se pudo listar cámaras, usando facingMode', err);
      startWithCamera(null);
    });
  } else {
    startWithCamera(null);
  }
}

// --- BarcodeDetector fallback ---
function startBarcodeDetector() {
  barcodeVideo = document.getElementById('barcode-video');
  barcodeCanvas = document.getElementById('barcode-canvas');

  const constraints = { video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } } };
  setCameraStatus('Iniciando detector nativo de códigos...');

  navigator.mediaDevices.getUserMedia(constraints).then(stream => {
    barcodeStream = stream;
    barcodeVideo.srcObject = stream;
    barcodeVideo.style.display = 'block';
    document.getElementById('reader-container').classList.remove('seccion-oculta');
    document.getElementById('btn-escanear').innerHTML = '<i class="fa-solid fa-stop"></i> Detener Cámara';

    // Esperar a que el video tenga datos
    barcodeVideo.addEventListener('loadeddata', () => {
      // ajustar canvas al tamaño
      barcodeCanvas.width = barcodeVideo.videoWidth || 640;
      barcodeCanvas.height = barcodeVideo.videoHeight || 480;

      barcodeInterval = setInterval(async () => {
        try {
          const ctx = barcodeCanvas.getContext('2d');
          ctx.drawImage(barcodeVideo, 0, 0, barcodeCanvas.width, barcodeCanvas.height);
          const bitmap = barcodeCanvas; // detect acepta ImageBitmap or canvas
          const barcodes = await barcodeDetector.detect(bitmap);
          if (barcodes && barcodes.length) {
            // Tomamos el primero
            const code = barcodes[0].rawValue;
            console.log('BarcodeDetector decoded:', code, barcodes[0]);
            procesarCodigoDeBarras(code);
            detenerEscaneo();
          }
        } catch (e) {
          console.debug('Barcode detect error', e);
        }
      }, 500);
      clearCameraError();
      setCameraStatus('Detector activo: espera el código...');
    }, { once: true });
  }).catch(err => {
    console.error('getUserMedia para BarcodeDetector falló:', err);
    showCameraError('No se pudo acceder a la cámara para el detector nativo.');
  });
}

function stopBarcodeDetector() {
  if (barcodeInterval) {
    clearInterval(barcodeInterval);
    barcodeInterval = null;
  }
  if (barcodeVideo) {
    barcodeVideo.pause();
    barcodeVideo.srcObject = null;
    barcodeVideo.style.display = 'none';
  }
  if (barcodeStream) {
    barcodeStream.getTracks().forEach(t => t.stop());
    barcodeStream = null;
  }
  barcodeDetector = null;
  clearCameraError();
}

function detenerEscaneo() {
  // Detener Html5Qrcode si está activo
  if (html5QrCode) {
    html5QrCode.stop().then(() => {
      document.getElementById("reader-container").classList.add("seccion-oculta");
      document.getElementById("btn-escanear").innerHTML = '<i class="fa-solid fa-camera"></i> Iniciar Escáner';
      clearCameraError();
    }).catch(() => {
      document.getElementById("reader-container").classList.add("seccion-oculta");
      document.getElementById("btn-escanear").innerHTML = '<i class="fa-solid fa-camera"></i> Iniciar Escáner';
    });
    html5QrCode = null;
  }

  // Detener BarcodeDetector fallback si está activo
  stopBarcodeDetector();
}

function showCameraError(msg) {
  const el = document.getElementById("camera-error");
  if (el) {
    el.innerText = msg;
    el.style.display = "block";
    el.style.color = "#b71c1c";
    el.style.background = "rgba(183,28,28,0.05)";
    el.style.padding = "6px 8px";
    el.style.borderRadius = "6px";
  } else {
    alert(msg);
  }
}

function clearCameraError() {
  const el = document.getElementById("camera-error");
  if (el) {
    el.innerText = "";
    el.style.display = "none";
    el.style.color = "";
    el.style.background = "";
    el.style.padding = "";
    el.style.borderRadius = "";
  }
}

function setCameraStatus(msg) {
  const el = document.getElementById("camera-error");
  if (el) {
    el.innerText = msg;
    el.style.display = "block";
    el.style.color = "#0b6623";
    el.style.background = "rgba(11,102,35,0.05)";
    el.style.padding = "6px 8px";
    el.style.borderRadius = "6px";
  }
}

function procesarCodigoDeBarras(codigo) {
  const resDiv = document.getElementById("resultado-escaneo");

  // 1. Verificar si ya se usó
  if (codigosUsados.includes(codigo)) {
    resDiv.innerHTML = `<div class='error-scan'>❌ Código <b>${codigo}</b> ya fue registrado hoy.</div>`;
    return;
  }

  // 2. Buscar en "base de datos"
  const producto = productosDB[codigo];
  const configGeneral = {
    plastico: { contenedor: "Contenedor amarillo", co2: 0.08 },
    papel: { contenedor: "Contenedor azul", co2: 0.05 },
    vidrio: { contenedor: "Contenedor verde", co2: 0.25 },
    organico: { contenedor: "Contenedor orgánico", co2: 0.03 }
  };

  let infoFinal = null;
  if (producto) {
    infoFinal = {
      nombre: producto.nombre,
      contenedor: configGeneral[producto.categoria]?.contenedor || "Punto limpio",
      co2: producto.co2,
      categoria: producto.categoria
    };
  } else {
    // Si no está en DB, asignar uno genérico basado en el primer dígito como simulacro
    infoFinal = {
      nombre: "Producto Desconocido",
      contenedor: "Contenedor Amarillo (Genérico)",
      co2: 0.05,
      categoria: "plastico"
    };
  }

  // 3. Registrar y sumar puntos
  registrarPuntos(codigo, infoFinal);
  detenerEscaneo();
}

function registrarPuntos(codigo, info) {
  const resDiv = document.getElementById("resultado-escaneo");

  co2Total += info.co2;
  contadorResiduos++;
  codigosUsados.push(codigo);

  // Registrar material (basado en la categoría de info o productoDB)
  const cat = info.categoria || "plastico";
  if (materialesStats[cat] !== undefined) {
    materialesStats[cat]++;
  } else {
    materialesStats.organico++; // Por defecto a orgánico si es desconocido
  }
  materialesStats.total++;

  resDiv.innerHTML = `
    <div class='exito-scan'>
      ✅ <b>¡Registrado con éxito!</b><br>
      📦 ${info.nombre} (${codigo})<br>
      🗑️ Tirar en: ${info.contenedor}<br>
      🌱 Ganaste: <b>${info.co2.toFixed(2)} kg</b> de CO₂
    </div>
  `;

  document.getElementById("puntuacion").innerText = co2Total.toFixed(2);
  document.getElementById("contador").innerText = contadorResiduos;

  registrarActividad(codigo, info);
  actualizarRacha();
  actualizarNivel();
  verificarLogros();
  actualizarEstadisticasExtendidas();
  actualizarRecompensas();
  guardarUsuario();
  actualizarRanking();
  actualizarEstadisticasGlobales();
  actualizarRankingCentros();

  // Nuevas funciones
  actualizarPerfil();
  actualizarRetos();
  actualizarProgresoRecompensas();
  actualizarNivelMini();
  actualizarRachaStats();
}

function actualizarEstadisticasExtendidas() {
  // 1. Resumen numérico
  const co2El = document.getElementById("co2-total-num");
  if (co2El) co2El.innerText = co2Total.toFixed(2);

  // 2. Reparto de materiales (Barras)
  if (materialesStats.total > 0) {
    const pP = (materialesStats.plastico / materialesStats.total) * 100;
    const pA = (materialesStats.papel / materialesStats.total) * 100;
    const pV = (materialesStats.vidrio / materialesStats.total) * 100;
    const pO = (materialesStats.organico / materialesStats.total) * 100;

    actualizarBarra("plastico", pP);
    actualizarBarra("papel", pA);
    actualizarBarra("vidrio", pV);
    actualizarBarra("otros", pO);
  }

  // 3. Equivalencias
  // - 1 kg CO2 eq. a ~6 km en coche de gasolina pequeño.
  // - 1 kg CO2 eq. a ~40 horas de bombilla LED (10W).
  // - 1 kg CO2 eq. a ~2 duchas calientes (ahorro energía).

  if (document.getElementById("equiv-km")) {
    document.getElementById("equiv-km").innerText = (co2Total * 6).toFixed(1) + " km";
    document.getElementById("equiv-horas").innerText = (co2Total * 40).toFixed(0) + "h";
    document.getElementById("equiv-duchas").innerText = (co2Total * 2).toFixed(0);
  }
}

function actualizarBarra(id, porcentaje) {
  const label = document.getElementById("perc-" + id);
  const bar = document.getElementById("bar-" + id);
  if (label) label.innerText = Math.round(porcentaje) + "%";
  if (bar) bar.style.width = porcentaje + "%";
}

/**********************
 * LOGROS Y HISTORIAL
 **********************/
function registrarActividad(codigo, info) {
  const item = {
    fecha: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    nombre: info.nombre,
    co2: info.co2
  };

  historialActividad.unshift(item);
  if (historialActividad.length > 5) historialActividad.pop();
  actualizarHistorialUI();
}

function actualizarHistorialUI() {
  const lista = document.getElementById("lista-historial");
  if (!lista) return;

  if (historialActividad.length === 0) {
    lista.innerHTML = '<li class="vacio">Aún no has reciclado nada</li>';
    return;
  }

  lista.innerHTML = historialActividad.map(item => `
    <li>
      <span><b>${item.nombre}</b> <small>(${item.fecha})</small></span>
      <span class="co2-historial">+${item.co2.toFixed(2)} kg</span>
    </li>
  `).join("");
}

function verificarLogros() {
  const nuevosLogros = [];

  if (contadorResiduos >= 1 && !logrosDesbloqueados.includes("logro-1")) nuevosLogros.push("logro-1");
  if (rachaDiaria >= 3 && !logrosDesbloqueados.includes("logro-2")) nuevosLogros.push("logro-2");
  if (contadorResiduos >= 20 && !logrosDesbloqueados.includes("logro-3")) nuevosLogros.push("logro-3");
  if (co2Total >= 10 && !logrosDesbloqueados.includes("logro-4")) nuevosLogros.push("logro-4");

  if (nuevosLogros.length > 0) {
    logrosDesbloqueados.push(...nuevosLogros);
    actualizarLogrosUI();
    // Podrías añadir un alert o notificación cool aquí
  }
}

function actualizarLogrosUI() {
  logrosDesbloqueados.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove("bloqueado");
      el.classList.add("desbloqueado");
    }
  });
}

/**********************
 * GAMIFICACIÓN: NIVELES Y RACHAS
 **********************/
function actualizarNivel() {
  const niveles = [
    { nombre: "Semilla", min: 0, max: 5 },
    { nombre: "Brote", min: 5, max: 15 },
    { nombre: "Pequeño Árbol", min: 15, max: 30 },
    { nombre: "Guardián del Bosque", min: 30, max: 50 },
    { nombre: "Héroe del Planeta", min: 50, max: 100 }
  ];

  let nivelActual = niveles[0];
  for (let i = niveles.length - 1; i >= 0; i--) {
    if (co2Total >= niveles[i].min) {
      nivelActual = niveles[i];
      break;
    }
  }

  const progreso = ((co2Total - nivelActual.min) / (nivelActual.max - nivelActual.min)) * 100;
  const porcentaje = Math.min(Math.max(progreso, 0), 100);

  document.getElementById("nivel-nombre").innerText = `Nivel: ${nivelActual.nombre}`;
  document.getElementById("nivel-porcentaje").innerText = `${Math.floor(porcentaje)}%`;
  document.getElementById("barra-progreso-fill").style.width = `${porcentaje}%`;
}

function verificarRacha() {
  if (!ultimaFechaReciclaje) {
    rachaDiaria = 0;
  } else {
    const hoy = new Date().toDateString();
    const ultima = new Date(ultimaFechaReciclaje).toDateString();

    if (hoy !== ultima) {
      const ayer = new Date();
      ayer.setDate(ayer.getDate() - 1);
      if (ultima !== ayer.toDateString()) {
        rachaDiaria = 0; // Se perdió la racha
      }
    }
  }
  document.getElementById("racha-valor").innerText = `${rachaDiaria} días`;
}

function actualizarRacha() {
  const hoy = new Date().toDateString();
  if (ultimaFechaReciclaje !== hoy) {
    rachaDiaria++;
    ultimaFechaReciclaje = hoy;
  }
  document.getElementById("racha-valor").innerText = `${rachaDiaria} días`;
}

/**********************
 * RECOMPENSAS
 **********************/
function actualizarRecompensas() {
  document.querySelectorAll(".recompensa").forEach(r => {
    const objetivo = parseFloat(r.querySelector("span").innerText);
    if (co2Total >= objetivo) {
      r.classList.remove("bloqueada");
    }
  });
}

/**********************
 * RANKING
 **********************/
function actualizarRanking() {
  const lista = document.getElementById("rankingUsuarios");
  if (!lista) return;

  const ranking = [];

  for (let i = 0; i < localStorage.length; i++) {
    const clave = localStorage.key(i);
    if (clave.startsWith("eco_user_")) {
      const nombre = clave.replace("eco_user_", "");
      const datos = JSON.parse(localStorage.getItem(clave));
      ranking.push({ nombre, co2: datos.co2 });
    }
  }

  ranking.sort((a, b) => b.co2 - a.co2);
  lista.innerHTML = "";

  ranking.forEach((u, i) => {
    const li = document.createElement("li");
    li.innerHTML = `<span>${i + 1}. ${u.nombre}</span> <span>${u.co2.toFixed(2)} kg CO₂</span>`;
    lista.appendChild(li);
  });
}

/**********************
 * NAVEGACIÓN
 **********************/
function mostrarSeccion(seccion, event) {
  // Ocultar todas las secciones
  const secciones = document.querySelectorAll('.seccion-contenido');
  secciones.forEach(s => s.classList.add('seccion-oculta'));

  // Mostrar la sección seleccionada
  const seccionSeleccionada = document.getElementById('seccion-' + seccion);
  if (seccionSeleccionada) {
    seccionSeleccionada.classList.remove('seccion-oculta');
  }

  // Actualizar botones (quitar clase activo de todos y ponerla al clicado)
  const botones = document.querySelectorAll('.boton-nav');
  botones.forEach(b => b.classList.remove('activo'));

  if (event) {
    event.currentTarget.classList.add('activo');
  } else {
    // Si no hay evento (ej: carga inicial), buscar el botón por texto o atributo
    // En este caso, el HTML ya viene con el de 'Inicio' activo por defecto.
  }
}

/**********************
 * SESIÓN AUTOMÁTICA
 **********************/
window.onload = () => {
  const ultimo = localStorage.getItem("eco_ultimo_usuario");
  if (ultimo) {
    usuario = ultimo;
    cargarUsuario();
    document.getElementById("loginPantalla").style.display = "none";
    actualizarRanking();
    actualizarRankingCentros();
    actualizarEstadisticasGlobales();
    obtenerUbicacion();
  }
};

/**********************
 * ESTADÍSTICAS GLOBALES DE MOLINA DE SEGURA
 **********************/
function actualizarEstadisticasGlobales() {
  let totalUsuarios = 0;
  let co2Global = 0;
  let objetosGlobal = 0;

  // Recorrer todos los usuarios en localStorage
  for (let i = 0; i < localStorage.length; i++) {
    const clave = localStorage.key(i);
    if (clave.startsWith("eco_user_")) {
      totalUsuarios++;
      const datos = JSON.parse(localStorage.getItem(clave));
      co2Global += datos.co2 || 0;
      objetosGlobal += datos.residuos || 0;
    }
  }

  // Actualizar UI
  const totalEl = document.getElementById("total-usuarios");
  const co2El = document.getElementById("co2-global");
  const objetosEl = document.getElementById("objetos-global");

  if (totalEl) totalEl.innerText = totalUsuarios;
  if (co2El) co2El.innerText = co2Global.toFixed(2);
  if (objetosEl) objetosEl.innerText = objetosGlobal;

  // Equivalencias globales
  // 1 árbol absorbe ~22kg de CO2 al año
  const arboles = (co2Global / 22).toFixed(1);
  // 1 kg CO2 = ~6 km en coche
  const kmGlobal = (co2Global * 6).toFixed(0);
  // 1 kg CO2 = ~2 kWh (aprox)
  const energiaKwh = (co2Global * 2).toFixed(0);

  const arbolesEl = document.getElementById("equiv-arboles");
  const kmGlobalEl = document.getElementById("equiv-km-global");
  const energiaEl = document.getElementById("equiv-energia");

  if (arbolesEl) arbolesEl.innerText = arboles;
  if (kmGlobalEl) kmGlobalEl.innerText = kmGlobal;
  if (energiaEl) energiaEl.innerText = energiaKwh;
}

/**********************
 * RANKING DE CENTROS EDUCATIVOS
 **********************/
function actualizarRankingCentros() {
  const lista = document.getElementById("rankingCentros");
  if (!lista) return;

  const centrosStats = {};

  // Recorrer todos los usuarios y agrupar por centro
  for (let i = 0; i < localStorage.length; i++) {
    const clave = localStorage.key(i);
    if (clave.startsWith("eco_user_")) {
      const datos = JSON.parse(localStorage.getItem(clave));
      const centro = datos.centro;

      if (centro) {
        if (!centrosStats[centro]) {
          centrosStats[centro] = { nombre: centro, co2: 0, usuarios: 0, objetos: 0 };
        }
        centrosStats[centro].co2 += datos.co2 || 0;
        centrosStats[centro].usuarios++;
        centrosStats[centro].objetos += datos.residuos || 0;
      }
    }
  }

  // Convertir a array y ordenar por CO2
  const ranking = Object.values(centrosStats).sort((a, b) => b.co2 - a.co2);

  lista.innerHTML = "";

  if (ranking.length === 0) {
    lista.innerHTML = '<li class="vacio">Aún no hay centros registrados</li>';
    return;
  }

  ranking.forEach((centro, i) => {
    const li = document.createElement("li");
    const medalla = i === 0 ? "🥇" : i === 1 ? "🥈" : i === 2 ? "🥉" : `${i + 1}.`;
    const esActual = centro.nombre === centroEducativo ? ' class="mi-centro"' : '';

    li.innerHTML = `
      <div class="centro-info"${esActual}>
        <span class="centro-posicion">${medalla}</span>
        <div class="centro-detalles">
          <span class="centro-nombre">${centro.nombre}</span>
          <span class="centro-usuarios"><i class="fa-solid fa-user-group"></i> ${centro.usuarios} estudiantes</span>
        </div>
      </div>
      <div class="centro-stats">
        <span class="centro-co2">${centro.co2.toFixed(2)} kg CO₂</span>
        <span class="centro-objetos"><i class="fa-solid fa-recycle"></i> ${centro.objetos}</span>
      </div>
    `;

    if (centro.nombre === centroEducativo) {
      li.classList.add("mi-centro-item");

      // Actualizar info del centro en el perfil
      actualizarInfoCentroPerfil(centro, i + 1);
    }

    lista.appendChild(li);
  });
}

/**********************
 * ACTUALIZAR PERFIL
 **********************/
function actualizarPerfil() {
  // Nombre de usuario
  const nombreEl = document.getElementById("perfil-nombre");
  if (nombreEl) nombreEl.innerText = usuario || "Usuario";

  // Centro educativo
  const centroEl = document.getElementById("perfil-centro");
  if (centroEl) centroEl.innerText = centroEducativo || "Sin centro asignado";

  const centroNombreEl = document.getElementById("centro-nombre-perfil");
  if (centroNombreEl) centroNombreEl.innerText = centroEducativo || "Sin centro";

  // Estadísticas del perfil
  const perfilCo2 = document.getElementById("perfil-co2");
  const perfilObjetos = document.getElementById("perfil-objetos");
  const perfilRacha = document.getElementById("perfil-racha");
  const perfilLogros = document.getElementById("perfil-logros");

  if (perfilCo2) perfilCo2.innerText = co2Total.toFixed(2);
  if (perfilObjetos) perfilObjetos.innerText = contadorResiduos;
  if (perfilRacha) perfilRacha.innerText = rachaDiaria;
  if (perfilLogros) perfilLogros.innerText = logrosDesbloqueados.length;

  // Nivel badge
  const nivelBadge = document.getElementById("perfil-nivel-badge");
  if (nivelBadge) {
    const niveles = [
      { nombre: "Semilla", emoji: "🌱", min: 0 },
      { nombre: "Brote", emoji: "🌿", min: 5 },
      { nombre: "Pequeño Árbol", emoji: "🌳", min: 15 },
      { nombre: "Guardián del Bosque", emoji: "🏕️", min: 30 },
      { nombre: "Héroe del Planeta", emoji: "🌍", min: 50 }
    ];

    let nivelActual = niveles[0];
    for (let i = niveles.length - 1; i >= 0; i--) {
      if (co2Total >= niveles[i].min) {
        nivelActual = niveles[i];
        break;
      }
    }
    nivelBadge.innerText = `${nivelActual.emoji} ${nivelActual.nombre}`;
  }
}

function actualizarInfoCentroPerfil(centro, posicion) {
  const posicionEl = document.getElementById("centro-posicion-actual");
  const usuariosEl = document.getElementById("centro-usuarios-count");
  const co2El = document.getElementById("centro-co2-total");

  if (posicionEl) posicionEl.innerText = `#${posicion}`;
  if (usuariosEl) usuariosEl.innerText = centro.usuarios;
  if (co2El) co2El.innerText = centro.co2.toFixed(2);
}

/**********************
 * ACTUALIZAR RETOS
 **********************/
function actualizarRetos() {
  // Reto 1: Recicla 5 objetos
  const reto1Progreso = document.getElementById("reto-1-progreso");
  const reto1Texto = document.getElementById("reto-1-texto");
  const reto1 = document.getElementById("reto-1");
  const progreso1 = Math.min((contadorResiduos / 5) * 100, 100);

  if (reto1Progreso) reto1Progreso.style.width = progreso1 + "%";
  if (reto1Texto) reto1Texto.innerText = `${Math.min(contadorResiduos, 5)}/5 objetos`;
  if (reto1 && progreso1 >= 100) reto1.classList.add("completado");

  // Reto 2: Ahorra 2 kg de CO₂
  const reto2Progreso = document.getElementById("reto-2-progreso");
  const reto2Texto = document.getElementById("reto-2-texto");
  const reto2 = document.getElementById("reto-2");
  const progreso2 = Math.min((co2Total / 2) * 100, 100);

  if (reto2Progreso) reto2Progreso.style.width = progreso2 + "%";
  if (reto2Texto) reto2Texto.innerText = `${Math.min(co2Total, 2).toFixed(1)}/2 kg`;
  if (reto2 && progreso2 >= 100) reto2.classList.add("completado");

  // Reto 3: Mantén 3 días de racha
  const reto3Progreso = document.getElementById("reto-3-progreso");
  const reto3Texto = document.getElementById("reto-3-texto");
  const reto3 = document.getElementById("reto-3");
  const progreso3 = Math.min((rachaDiaria / 3) * 100, 100);

  if (reto3Progreso) reto3Progreso.style.width = progreso3 + "%";
  if (reto3Texto) reto3Texto.innerText = `${Math.min(rachaDiaria, 3)}/3 días`;
  if (reto3 && progreso3 >= 100) reto3.classList.add("completado");
}

/**********************
 * ACTUALIZAR PROGRESO RECOMPENSAS
 **********************/
function actualizarProgresoRecompensas() {
  const co2El = document.getElementById("co2-recompensas");
  if (co2El) co2El.innerText = co2Total.toFixed(2);

  const recompensas = [
    { nombre: "Café gratis", objetivo: 5 },
    { nombre: "Entrada cultural", objetivo: 10 },
    { nombre: "Árbol plantado", objetivo: 20 },
    { nombre: "Camiseta EcoMaps", objetivo: 50 }
  ];

  // Encontrar la próxima recompensa
  let proximaRecompensa = recompensas[recompensas.length - 1];
  for (const r of recompensas) {
    if (co2Total < r.objetivo) {
      proximaRecompensa = r;
      break;
    }
  }

  const nombreEl = document.getElementById("proxima-recompensa-nombre");
  const barraEl = document.getElementById("barra-recompensa-fill");
  const faltaEl = document.getElementById("falta-recompensa");

  if (nombreEl) nombreEl.innerText = proximaRecompensa.nombre;

  const progreso = Math.min((co2Total / proximaRecompensa.objetivo) * 100, 100);
  if (barraEl) barraEl.style.width = progreso + "%";

  const falta = Math.max(proximaRecompensa.objetivo - co2Total, 0);
  if (faltaEl) {
    if (falta <= 0) {
      faltaEl.innerText = "¡Ya puedes canjearlo!";
    } else {
      faltaEl.innerText = `Te faltan ${falta.toFixed(2)} kg`;
    }
  }
}

/**********************
 * CERRAR SESIÓN
 **********************/
function cerrarSesion() {
  if (confirm("¿Estás seguro de que quieres cerrar sesión?")) {
    localStorage.removeItem("eco_ultimo_usuario");
    location.reload();
  }
  const curiosidades = [
    "Reciclar una lata de aluminio ahorra energía suficiente para usar una TV durante 3 horas.",
    "El vidrio puede reciclarse infinitamente sin perder calidad.",
    "Reciclar papel reduce la deforestación y ahorra agua.",
    "El plástico reciclado puede convertirse en ropa o muebles.",
    "Reciclar 1 kg de papel ahorra más de 1 kg de CO₂.",
    "Una botella de plástico tarda 500 años en descomponerse.",
    "En España se generan 22 millones de toneladas de residuos al año.",
    "El 80% de lo que tiramos podría reciclarse."
  ];

  const indice = Math.floor(Math.random() * curiosidades.length);
  const el = document.getElementById("curiosidad-inicio");
  if (el) el.textContent = curiosidades[indice];

  // También actualizar la curiosidad del perfil
  const elPerfil = document.getElementById("curiosidad");
  if (elPerfil) elPerfil.textContent = curiosidades[indice];
}

// Registrar listener estable para el botón de búsqueda (evita problemas de type/submit)
document.addEventListener('DOMContentLoaded', () => {
  const btnBuscar = document.getElementById('btn-buscar');
  if (btnBuscar) {
    btnBuscar.addEventListener('click', buscarResiduo);
  }
  const btnLogin = document.getElementById('btn-login');
  if (btnLogin) {
    btnLogin.addEventListener('click', loginUsuario);
  }
});

/**********************
 * ACTUALIZAR NIVEL MINI (INICIO)
 **********************/
function actualizarNivelMini() {
  const niveles = [
    { nombre: "Semilla", min: 0 },
    { nombre: "Brote", min: 5 },
    { nombre: "Pequeño Árbol", min: 15 },
    { nombre: "Guardián", min: 30 },
    { nombre: "Héroe", min: 50 }
  ];

  let nivelActual = niveles[0];
  for (let i = niveles.length - 1; i >= 0; i--) {
    if (co2Total >= niveles[i].min) {
      nivelActual = niveles[i];
      break;
    }
  }

  const el = document.getElementById("nivel-nombre-mini");
  if (el) el.innerText = nivelActual.nombre;
}

/**********************
 * ACTUALIZAR RACHA STATS
 **********************/
function actualizarRachaStats() {
  const el = document.getElementById("racha-stats");
  if (el) el.innerText = rachaDiaria;
}

/**********************
 * GEOLOCALIZACIÓN SIMPLIFICADA
 **********************/
function obtenerUbicacion() {
  const direccionEl = document.getElementById("direccion-actual");
  const coordsEl = document.getElementById("ubicacion-coords-mini");

  if (!navigator.geolocation) {
    if (direccionEl) direccionEl.innerText = "Geolocalización no disponible";
    return;
  }

  if (direccionEl) direccionEl.innerText = "Obteniendo ubicación...";

  navigator.geolocation.getCurrentPosition(
    (posicion) => {
      const lat = posicion.coords.latitude;
      const lng = posicion.coords.longitude;
      ubicacionUsuario.lat = lat;
      ubicacionUsuario.lng = lng;

      // Mostrar coordenadas
      const latEl = document.getElementById("lat-value");
      const lngEl = document.getElementById("lng-value");
      if (latEl) latEl.innerText = lat.toFixed(5);
      if (lngEl) lngEl.innerText = lng.toFixed(5);
      if (coordsEl) coordsEl.style.display = "block";

      // Obtener dirección
      fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&zoom=18&addressdetails=1`)
        .then(response => response.json())
        .then(data => {
          if (data && data.display_name) {
            const partes = data.display_name.split(",");
            const direccionCorta = partes.slice(0, 3).join(",").trim();
            ubicacionUsuario.direccion = direccionCorta;
            if (direccionEl) direccionEl.innerText = direccionCorta;
          } else {
            if (direccionEl) direccionEl.innerText = "Molina de Segura, Murcia";
          }
        })
        .catch(() => {
          if (direccionEl) direccionEl.innerText = "Molina de Segura, Murcia";
        });
    },
    (error) => {
      let mensaje = "Molina de Segura";
      switch (error.code) {
        case error.PERMISSION_DENIED:
          mensaje = "Ubicación denegada";
          break;
        case error.POSITION_UNAVAILABLE:
          mensaje = "Ubicación no disponible";
          break;
        case error.TIMEOUT:
          mensaje = "Tiempo agotado";
          break;
      }
      if (direccionEl) direccionEl.innerText = mensaje;
    },
    { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
  );
}
