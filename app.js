/**********************
 * USUARIO Y ESTADO
 **********************/
let usuario = null;
let co2Total = 0;
let contadorResiduos = 0;

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
function loginUsuario() {
  const nombre = document.getElementById("nombreUsuario").value.trim();
  const password = document.getElementById("passwordUsuario").value.trim();

  if (!nombre || !password) {
    alert("Introduce usuario y contraseña");
    return;
  }

  const clave = "eco_user_" + nombre;
  let datos = JSON.parse(localStorage.getItem(clave));

  if (datos) {
    if (datos.password !== password) {
      alert("Contraseña incorrecta");
      return;
    }
  } else {
    datos = { password, co2: 0, residuos: 0 };
    localStorage.setItem(clave, JSON.stringify(datos));
  }

  usuario = nombre;
  localStorage.setItem("eco_ultimo_usuario", usuario);
  cargarUsuario();

  document.getElementById("loginPantalla").style.display = "none";
  actualizarRanking();
}

/**********************
 * CARGAR / GUARDAR
 **********************/
function cargarUsuario() {
  const datos = JSON.parse(localStorage.getItem("eco_user_" + usuario));
  if (!datos) return;

  co2Total = datos.co2;
  contadorResiduos = datos.residuos;

  document.getElementById("puntuacion").innerText = co2Total.toFixed(2);
  document.getElementById("contador").innerText = contadorResiduos;

  actualizarRecompensas();
}

function guardarUsuario() {
  const clave = "eco_user_" + usuario;
  const datos = JSON.parse(localStorage.getItem(clave));

  localStorage.setItem(clave, JSON.stringify({
    password: datos.password,
    co2: co2Total,
    residuos: contadorResiduos
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

  // 🔹 2. “IA” LOCAL (palabras clave)
  const categorias = {
    plastico: ["plastico", "botella", "envase", "bolsa"],
    papel: ["papel", "carton", "revista", "periodico"],
    vidrio: ["vidrio", "tarro", "frasco"],
    organico: ["comida", "fruta", "cascara"],
    electronico: ["movil", "ordenador", "pila", "bateria"]
  };

  let detectado = null;

  for (const categoria in categorias) {
    if (categorias[categoria].some(p => input.includes(p))) {
      detectado = categoria;
      break;
    }
  }

  if (!detectado) {
    resultado.innerText = "No reconocido. Prueba con otro nombre.";
    return;
  }

  const mapa = {
    plastico: { contenedor: "Contenedor amarillo", co2: 0.08 },
    papel: { contenedor: "Contenedor azul", co2: 0.05 },
    vidrio: { contenedor: "Contenedor verde", co2: 0.25 },
    organico: { contenedor: "Contenedor orgánico", co2: 0.03 },
    electronico: { contenedor: "Punto limpio", co2: 1.0 }
  };

  aplicarResultado(mapa[detectado], detectado + " (IA)");
}

/**********************
 * APLICAR RESULTADO
 **********************/
function aplicarResultado(dato, etiqueta) {
  const resultado = document.getElementById("resultado");

  co2Total += dato.co2;
  contadorResiduos++;

  resultado.innerHTML = `
    🗑️ ${dato.contenedor}<br>
    🌱 CO₂ ahorrado: <b>${dato.co2.toFixed(2)} kg</b><br>
    🤖 Detectado: ${etiqueta}
  `;

  document.getElementById("puntuacion").innerText = co2Total.toFixed(2);
  document.getElementById("contador").innerText = contadorResiduos;

  actualizarRecompensas();
  guardarUsuario();
  actualizarRanking();
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
    li.innerText = `${i + 1}. ${u.nombre} — ${u.co2.toFixed(2)} kg CO₂`;
    lista.appendChild(li);
  });
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
  }
};
