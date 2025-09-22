async function login() {
    const identifier  = document.getElementById("username").value.trim(); 
    const password = document.getElementById("password").value; 
    const msg = document.getElementById("msg"); 

    if (!identifier  || !password) {
        msg.style.color = "yellow"; 
        msg.innerText = "⚠️ Username/Email and password are required.";
        return; 
    }

    try {
        const res = await fetch('http://localhost:3000/auth/login', {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify({ identifier, password })
        });
        const data = await res.json(); 

        if (!res.ok) {
            msg.style.color = "red"; 
            msg.innerText = `❌ ${data.error || 'Login failed'}`;
            return; 
        }

        msg.style.color = "lightgreen"; 
        msg.innerText = "✅ Login Successful!";
        // Guarda el token JWT en localStorage
        localStorage.setItem('token', data.token); 
        setTimeout(() => location.href = 'dashboard_users.html', 800);

    } catch (err) {
        msg.style.color = "red"
        msg.innerText = "❌ Network error.";
        console.error(err); 
    }
}


async function register() {
    const u = document.getElementById('reg-username').value.trim(); 
    const e = document.getElementById('reg-email').value.trim(); 
    const p1 = document.getElementById('reg-password').value;
    const p2 = document.getElementById('reg-password2').value;
    const msg = document.getElementById('reg-msg'); 
    
    if (!u || !e || !p1 || !p2) {
        msg.style.color = "yellow"; 
        msg.innerText = "⚠️ Please fill in all fields.";
        return;
    }

    if ((!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e))) {
        msg.style.color = "red"; 
        msg.innerText = "❌ Please enter a valid email address.";
        return; 
    }

    if (p1 !== p2) {
        msg.style.color = "red"; 
        msg.innerText = "❌ Passwords do not match.";
        return;
    }

    try {
        const res = await fetch('http://localhost:3000/auth/register', {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json'  },
            body: JSON.stringify({ username: u, name: u, email: e, password: p1 })
        }); 

        const data = await res.json(); 

        if(!res.ok) {
            msg.style.color = 'red'; 
            msg.innerText = `❌ ${data.error || 'Register failed'}`;
            return;
        }
        msg.style.color = "ligthgreen"; 
        msg.innerText = "✅ Account created! You can login now.";
        setTimeout(showLogin, 1200); 
    } catch (err) {
        msg.style.color = "red"; 
        msg.innerText = "❌ Network error.";
        console.error(err); 
    }  
}

function showRegister() {
    document.getElementById('login-box').classList.add('hidden'); 
    document.getElementById('register-box').classList.remove('hidden'); 
}

function showLogin() {
    document.getElementById('register-box').classList.add('hidden'); 
    document.getElementById('login-box').classList.remove('hidden'); 
}


// +++++++ Dashboard Usuario *************

const API_BASE = 'http://localhost:3000'; // Se cambia si el host cambia 

const el = (id) => document.getElementById(id); 
const tbody = el('tbody'); 
const msg = el('msg'); 
const metalEl = el('meta'); 

function fmtDate(iso) {
    try {
        return new Date(iso).toLocaleString(); 
    }   catch {
        return iso || '';
    }
}

async function loadUsers() {
    const limit = Math.max(1, Math.min(100, Number(el('limit').value) || 10)); 
    const offset = Math.max(0, Number(el('offset').value) || 0); 

    // Muestra estado 
    msg.textContent = 'Loading...'; 
    tbody.innerHTML = ''; 

    // Token (si el users esta protegido, agrega Authorization)
    const token = localStorage.getItem('token'); 

    try {
        const res = await fetch(`${API_BASE}/users?limit=${limit}&offset=${offset}`, {
            headers: token ? { 'Authorization': `Bearer $token` } : {}
        }); 
        const body = await res.json(); 

        if (!res.ok) {
            msg.textContent = 'No users to show.'; 
        } else {
            msg.textContent = ''; 
        }

        for (const u of (body.data || [] )) {
            const tr = document.createElement('tr'); 
            tr.innerHTML = `
            <td>${u.name || ``}</td>
            <td>${u.email || ``}</td>
            <td>${fmtDate(u.createdAt)}</td>
            <td class="muted">${u._id || ``}</td>
            `;
            tbody.appendChild(tr); 
        }

        // Meta y control de paginacion 
        const total = body?.meta?.total ?? 0;
        metalEl.textContent = `Total: ${total} • Showing ${body.data?.length || 0} • limit=${limit} • offset=${offset}`;

        // Habilitar/deshabilitar botones
        el('prev').disabled = offset <= 0; 
        el('next').disabled = offset + limit >= total; 
    }   catch (e) {
        console.error(e); 
        msg.textContent = '❌ Network error.';
    }
}

// Navegacion 
el('btnLoad').addEventListener('click', loadUsers); 
el('prev').addEventListener('click', () => {
    const limit = Math.max(1, Math.min(100, Number(el('limit').value) || 10 ));
    const offset = Math.max(0, Number(el('offset').value) || 0); 
    el('offset').value = Math.max(0, offset - limit);
    loadUsers(); 
}); 
el('next').addEventListener('click', () => {
    const limit = Math.max(1, Math.min(100, Number(el('limit').value) || 10 )); 
    const offset = Math.max(0, Number(el('offset').value) || 0);
    el('offset').value = offset + limit; 
    loadUsers(); 
}); 

function logout() {
    try {
        localStorage.removeItem('token'); 
        sessionStorage.clear(); 
        }   catch (_) {}
        location.replace('index.html'); 
        }        
        window.addEventListener('pageshow', (e) => {
            if (e.persisted) location.reload(); 
        }); 
        document.getElementById('logoutBtn').addEventListener('click', logout);

            

// Carga inicial 
document.addEventListener('DOMContentLoaded', () => {
    el('baseUrl').textContent = API_BASE; 
    loadUsers(); 
}); 








