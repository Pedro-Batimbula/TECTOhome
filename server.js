require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const pool = require('./db');

if (!process.env.JWT_SECRET) {
  console.error('Falta JWT_SECRET no .env');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SETUP_KEY = process.env.ADMIN_SETUP_KEY || '';
const COOKIE = 'sessao';
const DIAS = 7;
const HASH_FALSO = bcrypt.hashSync('nao-existe', 10);

const PROVINCIAS = ['Luanda', 'Benguela', 'Huambo', 'Huíla', 'Cabinda', 'Malanje', 'Uíge', 'Namibe'];
const PLANOS = ['basico', 'medio', 'premium'];
const ANUNCIANTES = ['proprietario', 'intermediario'];
const CATEGORIAS_HABITACAO = ['casa', 'apartamento'];
const CATEGORIAS_COMERCIAL = ['loja', 'armazem', 'escritorio'];
const CATEGORIAS = [...CATEGORIAS_HABITACAO, ...CATEGORIAS_COMERCIAL, 'terreno'];
const PRECO_ACESSO = { medio: 3000, premium: 5000 };
/* Limites em Kz: até 'medio' é Básico, até 'premium' é Médio, acima é Premium. AJUSTA ESTES VALORES. */
const LIMITES_PLANO = {
  venda: { medio: 10000000, premium: 50000000 },
  arrendamento: { medio: 60000, premium: 1200000 },
};
const planoPorPreco = (tipo, preco) => {
  const l = LIMITES_PLANO[tipo];
  return preco <= l.medio ? 'basico' : preco <= l.premium ? 'medio' : 'premium';
};
const DIAS_ACESSO = 3;
const EXT = {
  'application/pdf': '.pdf',
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
};
const EXT_IMG = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
};
const MAX_FOTOS = 8;
const PASTA_UPLOADS = process.env.UPLOADS_DIR || path.join(__dirname, 'uploads');
const PASTA_DOCS = path.join(PASTA_UPLOADS, 'docs');
const PASTA_FOTOS = path.join(PASTA_UPLOADS, 'fotos');
fs.mkdirSync(PASTA_DOCS, { recursive: true });
fs.mkdirSync(PASTA_FOTOS, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) =>
      cb(null, file.fieldname === 'fotos' ? PASTA_FOTOS : PASTA_DOCS),
    filename: (req, file, cb) =>
      cb(null, crypto.randomBytes(16).toString('hex') + EXT[file.mimetype]),
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 + MAX_FOTOS },
  fileFilter: (req, file, cb) => {
    const tipos = ['doc', 'comprovativo'].includes(file.fieldname) ? EXT : file.fieldname === 'fotos' ? EXT_IMG : null;
    cb(null, Boolean(tipos && tipos[file.mimetype]));
  },
});

const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

const limitar = (minutos, limite, erro, extra = {}) =>
  rateLimit({
    windowMs: minutos * 60 * 1000,
    limit: limite,
    standardHeaders: true,
    legacyHeaders: false,
    message: { erro },
    ...extra,
  });
const limiteLogin = limitar(15, 10, 'Demasiadas tentativas. Tente novamente dentro de 15 minutos.', {
  skipSuccessfulRequests: true,
});
const limiteRegisto = limitar(60, 10, 'Demasiados registos a partir desta rede. Tente mais tarde.');
const limiteAdminInicial = limitar(15, 5, 'Demasiadas tentativas. Tente novamente dentro de 15 minutos.');
const limiteSenha = limitar(15, 10, 'Demasiadas tentativas. Tente novamente dentro de 15 minutos.', {
  skipSuccessfulRequests: true,
});

const app = express();
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'casas.html')));

/* ---------- Sessão ---------- */
const opcoesCookie = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
};

function darSessao(res, u) {
  const token = jwt.sign({ id: String(u.id) }, JWT_SECRET, { expiresIn: DIAS + 'd' });
  res.cookie(COOKIE, token, { ...opcoesCookie, maxAge: DIAS * 24 * 3600 * 1000 });
}

const publico = (u) => ({
  id: Number(u.id),
  nome: u.nome || null,
  telefone: u.telefone || null,
  email: u.email || null,
  papel: u.papel || null,
});

async function utilizadorAtual(req) {
  const token = req.cookies[COOKIE];
  if (!token) return null;
  try {
    const { id } = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query(
      'SELECT id, nome, telefone, email, papel FROM utilizadores WHERE id = $1',
      [id]
    );
    return rows[0] || null;
  } catch {
    return null;
  }
}

async function exigirSessao(req, res, next) {
  const u = await utilizadorAtual(req);
  if (!u) return res.status(401).json({ erro: 'Entre na sua conta para anunciar.' });
  req.utilizador = u;
  next();
}

/* ---------- Contas ---------- */
app.post('/api/registo', limiteRegisto, async (req, res) => {
  const nome = String(req.body.nome || '').trim();
  const telefone = String(req.body.telefone || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const senha = String(req.body.senha || '');

  if (nome.length < 2 || nome.length > 100)
    return res.status(400).json({ erro: 'Indique o seu nome.' });
  if (telefone.length > 20 || telefone.replace(/\D/g, '').length < 9)
    return res.status(400).json({ erro: 'Indique um telefone válido.' });
  if (email.length > 150 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    return res.status(400).json({ erro: 'Indique um email válido.' });
  if (senha.length < 6 || senha.length > 72)
    return res.status(400).json({ erro: 'A palavra-passe deve ter pelo menos 6 caracteres.' });

  try {
    const hash = await bcrypt.hash(senha, 10);
    const { rows } = await pool.query(
      `INSERT INTO utilizadores (nome, telefone, email, senha_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, nome, telefone, email, papel`,
      [nome, telefone, email, hash]
    );
    darSessao(res, rows[0]);
    res.status(201).json(publico(rows[0]));
  } catch (e) {
    if (e.code === '23505')
      return res.status(409).json({ erro: 'Este email já tem conta. Use "Entrar".' });
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível criar a conta. Tente novamente.' });
  }
});

app.post('/api/login', limiteLogin, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const senha = String(req.body.senha || '');

  try {
    const { rows } = await pool.query(
      'SELECT id, nome, email, papel, senha_hash FROM utilizadores WHERE lower(email) = $1',
      [email]
    );
    const u = rows[0];
    const ok = await bcrypt.compare(senha, u ? u.senha_hash : HASH_FALSO);
    if (!u || !ok)
      return res.status(401).json({ erro: 'Email ou palavra-passe incorrectos.' });

    darSessao(res, u);
    res.json(publico(u));
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível entrar. Tente novamente.' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE, opcoesCookie);
  res.json({ ok: true });
});

app.get('/api/eu', async (req, res) => {
  const u = await utilizadorAtual(req);
  res.json(u ? publico(u) : null);
});

app.post('/api/eu/senha', exigirSessao, limiteSenha, async (req, res) => {
  const atual = String(req.body.atual || '');
  const nova = String(req.body.nova || '');
  if (nova.length < 6 || nova.length > 72)
    return res.status(400).json({ erro: 'A nova palavra-passe deve ter pelo menos 6 caracteres.' });
  try {
    const { rows } = await pool.query('SELECT senha_hash FROM utilizadores WHERE id = $1', [req.utilizador.id]);
    if (!rows[0] || !(await bcrypt.compare(atual, rows[0].senha_hash)))
      return res.status(400).json({ erro: 'A palavra-passe actual está incorrecta.' });
    const hash = await bcrypt.hash(nova, 10);
    await pool.query('UPDATE utilizadores SET senha_hash = $1 WHERE id = $2', [hash, req.utilizador.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível mudar a palavra-passe.' });
  }
});

app.post('/api/eu/editar', exigirSessao, async (req, res) => {
  const nome = String(req.body.nome || '').trim();
  const telefone = String(req.body.telefone || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();

  if (nome.length < 2 || nome.length > 100)
    return res.status(400).json({ erro: 'Indique o seu nome.' });
  if (telefone.length > 20 || telefone.replace(/\D/g, '').length < 9)
    return res.status(400).json({ erro: 'Indique um telefone válido.' });
  if (email.length > 150 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    return res.status(400).json({ erro: 'Indique um email válido.' });

  try {
    const { rows } = await pool.query(
      `UPDATE utilizadores SET nome = $1, telefone = $2, email = $3
       WHERE id = $4
       RETURNING id, nome, telefone, email, papel`,
      [nome, telefone, email, req.utilizador.id]
    );
    res.json(publico(rows[0]));
  } catch (e) {
    if (e.code === '23505')
      return res.status(409).json({ erro: 'Este email já pertence a outra conta.' });
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível guardar. Tente novamente.' });
  }
});

/* ---------- Primeiro administrador ---------- */
const hashChave = (s) => crypto.createHash('sha256').update(String(s)).digest();

app.get('/api/admin/estado', async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT EXISTS (SELECT 1 FROM utilizadores WHERE papel = 'admin') AS existe"
    );
    res.json({ existe: rows[0].existe });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível verificar.' });
  }
});

app.post('/api/admin/inicial', limiteAdminInicial, async (req, res) => {
  if (!ADMIN_SETUP_KEY)
    return res.status(403).json({ erro: 'A criação do administrador está desactivada.' });
  if (!crypto.timingSafeEqual(hashChave(req.body.chave || ''), hashChave(ADMIN_SETUP_KEY)))
    return res.status(403).json({ erro: 'Chave de instalação incorrecta.' });

  const nome = String(req.body.nome || '').trim();
  const telefone = String(req.body.telefone || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const senha = String(req.body.senha || '');

  if (nome.length < 2 || nome.length > 100)
    return res.status(400).json({ erro: 'Indique o nome.' });
  if (telefone.length > 20 || telefone.replace(/\D/g, '').length < 9)
    return res.status(400).json({ erro: 'Indique um telefone válido.' });
  if (email.length > 150 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    return res.status(400).json({ erro: 'Indique um email válido.' });
  if (senha.length < 6 || senha.length > 72)
    return res.status(400).json({ erro: 'A palavra-passe deve ter pelo menos 6 caracteres.' });

  const cliente = await pool.connect();
  try {
    await cliente.query('BEGIN');
    await cliente.query('SELECT pg_advisory_xact_lock(7001)');
    const { rows: ja } = await cliente.query(
      "SELECT 1 FROM utilizadores WHERE papel = 'admin' LIMIT 1"
    );
    if (ja.length) {
      await cliente.query('ROLLBACK');
      return res.status(403).json({ erro: 'Já existe um administrador.' });
    }
    const hash = await bcrypt.hash(senha, 10);
    const { rows } = await cliente.query(
      `INSERT INTO utilizadores (nome, telefone, email, senha_hash, papel)
       VALUES ($1, $2, $3, $4, 'admin')
       RETURNING id, nome, telefone, email, papel`,
      [nome, telefone, email, hash]
    );
    await cliente.query('COMMIT');
    darSessao(res, rows[0]);
    res.status(201).json(publico(rows[0]));
  } catch (e) {
    await cliente.query('ROLLBACK').catch(() => {});
    if (e.code === '23505')
      return res.status(409).json({ erro: 'Este email já tem conta. Use outro email.' });
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível criar o administrador.' });
  } finally {
    cliente.release();
  }
});

async function planosActivos(u) {
  if (!u) return new Set();
  if (u.papel === 'admin') return new Set(['medio', 'premium']);
  const { rows } = await pool.query(
    `SELECT DISTINCT plano FROM acessos
     WHERE utilizador_id = $1 AND pago = true AND expira_em > now()`,
    [u.id]
  );
  return new Set(rows.map((r) => r.plano));
}

/* ---------- Anúncios (público) ---------- */
app.get('/api/anuncios', async (req, res) => {
  try {
    const { q, tipo, provincia, quartos, max, categoria } = req.query;
    const cond = ["estado = 'publicado'", 'concluido_em IS NULL', '(expira_em IS NULL OR expira_em > now())'];
    const val = [];
    const add = (sql, v) => {
      val.push(v);
      cond.push(sql.replaceAll('?', '$' + val.length));
    };

    if (q) add('(bairro ILIKE ? OR municipio ILIKE ? OR provincia ILIKE ? OR titulo ILIKE ?)', `%${q}%`);
    if (['venda', 'arrendamento'].includes(tipo)) add('tipo = ?', tipo);
    if (provincia) add('provincia = ?', provincia);
    if (CATEGORIAS.includes(categoria)) add('categoria = ?', categoria);
    if (Number(quartos) > 0) add('quartos >= ?', Number(quartos));
    if (Number(max) > 0) add('preco <= ?', Number(max));

    const { rows } = await pool.query(
      `SELECT id, tipo, categoria, titulo, descricao, preco, provincia, municipio, bairro,
              quartos, banhos, area_m2, salas, cozinhas, varandas, quintal, contacto,
              plano, anunciante,
              GREATEST(0, CEIL(EXTRACT(EPOCH FROM (expira_em - now())) / 86400))::int AS dias,
              (SELECT COALESCE(json_agg(f.caminho ORDER BY f.ordem), '[]'::json)
                 FROM fotos f WHERE f.anuncio_id = anuncios.id) AS fotos
       FROM anuncios
       WHERE ${cond.join(' AND ')}
       ORDER BY publicado_em DESC NULLS LAST, id DESC
       LIMIT 100`,
      val
    );
    const livres = await planosActivos(await utilizadorAtual(req));
    res.json(
      rows.map((r) => {
        const aberto = r.plano === 'basico' || livres.has(r.plano);
        return { ...r, contacto: aberto ? r.contacto : null, bloqueado: !aberto };
      })
    );
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível carregar os anúncios.' });
  }
});

/* ---------- Anúncios (criar) ---------- */
function receberDoc(req, res, next) {
  upload.fields([{ name: 'doc', maxCount: 1 }, { name: 'fotos', maxCount: MAX_FOTOS }])(req, res, (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE'
        ? 'Um dos ficheiros é demasiado grande (máx. 5 MB cada).'
        : 'Não foi possível receber os ficheiros (máx. 8 fotos).';
      return res.status(400).json({ erro: msg });
    }
    next();
  });
}

const inteiro = (v) => (/^\d+$/.test(String(v || '').trim()) ? Number(v) : NaN);
/* Campo opcional: vazio -> null; preenchido e inválido -> NaN */
const opcional = (v) => (String(v ?? '').trim() === '' ? null : inteiro(v));

app.post('/api/anuncios', exigirSessao, receberDoc, async (req, res) => {
  const doc = (req.files && req.files.doc && req.files.doc[0]) || null;
  const fotos = (req.files && req.files.fotos) || [];
  const apagarFicheiro = () => {
    [doc, ...fotos].forEach((f) => f && fs.unlink(f.path, () => {}));
  };
  const recusar = (msg) => {
    apagarFicheiro();
    return res.status(400).json({ erro: msg });
  };

  const b = req.body;
  const tipo = String(b.tipo || '');
  const categoria = String(b.categoria || 'casa');
  const anunciante = String(b.anunciante || '');
  const habitacao = CATEGORIAS_HABITACAO.includes(categoria);
  const comercial = CATEGORIAS_COMERCIAL.includes(categoria);
  const titulo = String(b.titulo || '').trim();
  const descricao = String(b.desc || '').trim();
  const prov = String(b.prov || '');
  const mun = String(b.mun || '').trim();
  const bairro = String(b.bairro || '').trim();
  const contacto = String(b.tel || '').trim();
  const preco = inteiro(b.preco);
  const area = inteiro(b.area);
  const plano = ['venda', 'arrendamento'].includes(tipo) && preco >= 1 ? planoPorPreco(tipo, preco) : 'basico';

  /* Campos que dependem da categoria: o que não pertence a ela fica NULL */
  const quartos = habitacao ? inteiro(b.quartos) : null;
  const banhos = habitacao ? inteiro(b.banhos) : comercial ? opcional(b.banhos) : null;
  const salas = habitacao ? opcional(b.salas) : null;
  const cozinhas = habitacao ? opcional(b.cozinhas) : null;
  const varandas = habitacao ? opcional(b.varandas) : null;
  const quintalTxt = String(b.quintal || '');
  const quintal = habitacao ? (quintalTxt === 'sim' ? true : quintalTxt === 'nao' ? false : null) : null;

  if (!['venda', 'arrendamento'].includes(tipo)) return recusar('Escolha o tipo de anúncio.');
  if (!ANUNCIANTES.includes(anunciante)) return recusar('Indique se é proprietário ou intermediário.');
  if (!CATEGORIAS.includes(categoria)) return recusar('Escolha a categoria do imóvel.');
  if (titulo.length < 5 || titulo.length > 70) return recusar('O título deve ter entre 5 e 70 caracteres.');
  if (!(preco >= 1 && preco <= 1e13)) return recusar('Indique um preço válido.');
  if (!PROVINCIAS.includes(prov)) return recusar('Escolha uma província.');
  if (mun.length < 2 || mun.length > 100) return recusar('Indique o município.');
  if (bairro.length < 2 || bairro.length > 100) return recusar('Indique o bairro ou referência.');
  if (!(area >= 1 && area <= 100000)) return recusar('Área inválida.');
  if (habitacao) {
    if (!(quartos >= 0 && quartos <= 50)) return recusar('Número de quartos inválido.');
    if (!(banhos >= 1 && banhos <= 50)) return recusar('Número de casas de banho inválido.');
    if (salas !== null && !(salas >= 0 && salas <= 50)) return recusar('Número de salas inválido.');
    if (cozinhas !== null && !(cozinhas >= 0 && cozinhas <= 50)) return recusar('Número de cozinhas inválido.');
    if (varandas !== null && !(varandas >= 0 && varandas <= 50)) return recusar('Número de varandas inválido.');
  }
  if (comercial && banhos !== null && !(banhos >= 0 && banhos <= 50))
    return recusar('Número de casas de banho inválido.');
  if (contacto.length > 20 || contacto.replace(/\D/g, '').length < 9)
    return recusar('Indique um telefone de contacto válido.');
  if (descricao.length < 10 || descricao.length > 2000)
    return recusar('A descrição deve ter entre 10 e 2000 caracteres.');
  if (!doc) return recusar('Junte o documento do imóvel (PDF, JPG, PNG ou WEBP).');
  if (fotos.length < 1) return recusar('Junte pelo menos uma foto.');

  try {
    const cliente = await pool.connect();
    let id;
    try {
      await cliente.query('BEGIN');
      const { rows } = await cliente.query(
        `INSERT INTO anuncios
           (utilizador_id, tipo, categoria, titulo, descricao, preco, provincia, municipio, bairro,
            quartos, banhos, area_m2, salas, cozinhas, varandas, quintal, contacto, documento_caminho, plano, anunciante, pago)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, true)
         RETURNING id`,
        [req.utilizador.id, tipo, categoria, titulo, descricao, preco, prov, mun, bairro,
         quartos, banhos, area, salas, cozinhas, varandas, quintal, contacto, doc.filename, plano, anunciante]
      );
      id = rows[0].id;
      for (let i = 0; i < fotos.length; i++) {
        await cliente.query(
          'INSERT INTO fotos (anuncio_id, caminho, ordem) VALUES ($1, $2, $3)',
          [id, fotos[i].filename, i]
        );
      }
      await cliente.query('COMMIT');
    } catch (e) {
      await cliente.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      cliente.release();
    }
    res.status(201).json({ id: Number(id) });
  } catch (e) {
    apagarFicheiro();
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível enviar o anúncio. Tente novamente.' });
  }
});

/* ---------- Os meus anúncios ---------- */
app.get('/api/meus-anuncios', exigirSessao, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT a.id, a.tipo, a.titulo, a.preco, a.provincia, a.municipio, a.estado, a.pago, a.motivo_rejeicao,
              (a.estado = 'publicado' AND a.concluido_em IS NULL AND a.expira_em IS NOT NULL AND a.expira_em <= now()) AS expirado,
              (a.concluido_em IS NOT NULL) AS concluido,
              GREATEST(0, CEIL(EXTRACT(EPOCH FROM (a.expira_em - now())) / 86400))::int AS dias,
              (SELECT COALESCE(json_agg(f.caminho ORDER BY f.ordem), '[]'::json)
                 FROM fotos f WHERE f.anuncio_id = a.id) AS fotos
       FROM anuncios a
       WHERE a.utilizador_id = $1
       ORDER BY a.criado_em DESC
       LIMIT 100`,
      [req.utilizador.id]
    );
    res.json(rows);
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível carregar os seus anúncios.' });
  }
});

app.post('/api/meus-anuncios/:id/remover', exigirSessao, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  try {
    const { rows: ficheirosFotos } = await pool.query(
      `SELECT f.caminho FROM fotos f
       JOIN anuncios a ON a.id = f.anuncio_id
       WHERE a.id = $1 AND a.utilizador_id = $2`,
      [id, req.utilizador.id]
    );
    const { rows } = await pool.query(
      'DELETE FROM anuncios WHERE id = $1 AND utilizador_id = $2 RETURNING documento_caminho',
      [id, req.utilizador.id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Anúncio não encontrado.' });
    fs.unlink(caminhoDoc(rows[0].documento_caminho), () => {});
    ficheirosFotos.forEach((f) => fs.unlink(caminhoFoto(f.caminho), () => {}));
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível remover.' });
  }
});

app.post('/api/meus-anuncios/:id/concluir', exigirSessao, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  try {
    const { rows } = await pool.query(
      `UPDATE anuncios SET concluido_em = now()
       WHERE id = $1 AND utilizador_id = $2
         AND estado = 'publicado' AND concluido_em IS NULL
         AND (expira_em IS NULL OR expira_em > now())
       RETURNING id`,
      [id, req.utilizador.id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Só pode marcar anúncios publicados e activos.' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível marcar o anúncio.' });
  }
});

app.post('/api/meus-anuncios/:id/renovar', exigirSessao, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  try {
    const { rows } = await pool.query(
      `UPDATE anuncios
       SET publicado_em = now(), expira_em = now() + interval '30 days'
       WHERE id = $1 AND utilizador_id = $2
         AND estado = 'publicado' AND concluido_em IS NULL
         AND expira_em IS NOT NULL AND expira_em <= now()
       RETURNING id`,
      [id, req.utilizador.id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Só pode renovar anúncios expirados.' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível renovar o anúncio.' });
  }
});

/* ---------- Fotos ---------- */
const caminhoFoto = (nome) => path.join(PASTA_FOTOS, path.basename(String(nome)));

app.get('/fotos/:nome', (req, res) => {
  if (!/^[a-f0-9]{32}\.(jpg|png|webp)$/.test(req.params.nome)) return res.status(404).end();
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'public, max-age=604800, immutable',
  });
  res.sendFile(caminhoFoto(req.params.nome), (err) => {
    if (err && !res.headersSent) res.status(404).end();
  });
});

/* ---------- Administração de anúncios ---------- */
async function exigirAdmin(req, res, next) {
  const u = await utilizadorAtual(req);
  if (!u || u.papel !== 'admin') return res.status(403).json({ erro: 'Sem permissão.' });
  req.utilizador = u;
  next();
}

const idValido = (v) => (/^\d{1,18}$/.test(String(v)) ? String(v) : null);
const caminhoDoc = (nome) => path.join(PASTA_DOCS, path.basename(String(nome)));

app.get('/api/admin/anuncios', exigirAdmin, async (req, res) => {
  const estado = req.query.estado === 'publicado' ? 'publicado' : 'pendente';
  try {
    const { rows } = await pool.query(
      `SELECT a.id, a.tipo, a.titulo, a.preco, a.provincia, a.municipio, a.pago, a.plano, a.anunciante,
              u.nome AS dono_nome, u.email AS dono_email,
              (a.expira_em IS NOT NULL AND a.expira_em <= now()) AS expirado,
              GREATEST(0, CEIL(EXTRACT(EPOCH FROM (a.expira_em - now())) / 86400))::int AS dias,
              (SELECT COALESCE(json_agg(f.caminho ORDER BY f.ordem), '[]'::json)
                 FROM fotos f WHERE f.anuncio_id = a.id) AS fotos
       FROM anuncios a
       JOIN utilizadores u ON u.id = a.utilizador_id
       WHERE a.estado = $1 AND a.motivo_rejeicao IS NULL
       ORDER BY a.criado_em DESC
       LIMIT 200`,
      [estado]
    );
    res.json(rows);
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível carregar os anúncios.' });
  }
});

app.get('/api/admin/anuncios/:id/documento', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  try {
    const { rows } = await pool.query(
      'SELECT documento_caminho FROM anuncios WHERE id = $1',
      [id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Anúncio não encontrado.' });
    res.set('X-Content-Type-Options', 'nosniff');
    res.sendFile(caminhoDoc(rows[0].documento_caminho), (err) => {
      if (err && !res.headersSent)
        res.status(404).json({ erro: 'Documento não encontrado.' });
    });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível abrir o documento.' });
  }
});

app.post('/api/admin/anuncios/:id/pago', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  try {
    const { rows } = await pool.query(
      "UPDATE anuncios SET pago = true WHERE id = $1 AND estado = 'pendente' RETURNING id",
      [id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Anúncio pendente não encontrado.' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível confirmar a taxa.' });
  }
});

app.post('/api/admin/anuncios/:id/publicar', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  try {
    const { rows } = await pool.query(
      `UPDATE anuncios
       SET estado = 'publicado', publicado_em = now(), expira_em = now() + interval '30 days'
       WHERE id = $1 AND estado = 'pendente' AND pago = true AND motivo_rejeicao IS NULL
       RETURNING id`,
      [id]
    );
    if (!rows[0])
      return res.status(409).json({ erro: 'Confirme primeiro o pagamento da taxa.' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível publicar.' });
  }
});

app.post('/api/admin/anuncios/:id/rejeitar', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  const motivo = String(req.body.motivo || '').trim();
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  if (motivo.length < 3 || motivo.length > 300)
    return res.status(400).json({ erro: 'Escreva o motivo da rejeição (3 a 300 caracteres).' });
  try {
    const { rows } = await pool.query(
      "UPDATE anuncios SET motivo_rejeicao = $1 WHERE id = $2 AND estado = 'pendente' RETURNING id",
      [motivo, id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Anúncio pendente não encontrado.' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível rejeitar.' });
  }
});

app.post('/api/admin/anuncios/:id/plano', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  const plano = String(req.body.plano || '');
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  if (!PLANOS.includes(plano)) return res.status(400).json({ erro: 'Plano inválido.' });
  try {
    const { rows } = await pool.query(
      'UPDATE anuncios SET plano = $1 WHERE id = $2 RETURNING id',
      [plano, id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Anúncio não encontrado.' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível mudar o plano.' });
  }
});

app.post('/api/admin/anuncios/:id/remover', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Anúncio inválido.' });
  try {
    const { rows: ficheirosFotos } = await pool.query(
      'SELECT caminho FROM fotos WHERE anuncio_id = $1',
      [id]
    );
    const { rows } = await pool.query(
      'DELETE FROM anuncios WHERE id = $1 RETURNING documento_caminho',
      [id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Anúncio não encontrado.' });
    fs.unlink(caminhoDoc(rows[0].documento_caminho), () => {});
    ficheirosFotos.forEach((f) => fs.unlink(caminhoFoto(f.caminho), () => {}));
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível remover.' });
  }
});

/* ---------- Acessos (planos de consulta) ---------- */
app.get('/api/acessos', exigirSessao, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, plano, pago,
              (comprovativo_caminho IS NOT NULL) AS comprovativo,
              (pago AND expira_em <= now()) AS expirado,
              GREATEST(0, CEIL(EXTRACT(EPOCH FROM (expira_em - now())) / 86400))::int AS dias
       FROM acessos WHERE utilizador_id = $1
       ORDER BY criado_em DESC LIMIT 50`,
      [req.utilizador.id]
    );
    res.json(rows.map((r) => ({ ...r, id: Number(r.id), preco: PRECO_ACESSO[r.plano] })));
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível carregar os acessos.' });
  }
});

app.post('/api/acessos', exigirSessao, async (req, res) => {
  const plano = String(req.body.plano || '');
  if (!PRECO_ACESSO[plano])
    return res.status(400).json({ erro: 'Escolha o plano médio ou premium.' });
  try {
    const { rows: activo } = await pool.query(
      `SELECT 1 FROM acessos
       WHERE utilizador_id = $1 AND plano = $2 AND pago = true AND expira_em > now() LIMIT 1`,
      [req.utilizador.id, plano]
    );
    if (activo.length) return res.status(409).json({ erro: 'Já tem acesso activo a este plano.' });

    const { rows: ja } = await pool.query(
      'SELECT id, (comprovativo_caminho IS NOT NULL) AS comprovativo FROM acessos WHERE utilizador_id = $1 AND plano = $2 AND pago = false LIMIT 1',
      [req.utilizador.id, plano]
    );
    if (ja[0]) return res.json({ id: Number(ja[0].id), plano, preco: PRECO_ACESSO[plano], comprovativo: ja[0].comprovativo });

    const { rows } = await pool.query(
      'INSERT INTO acessos (utilizador_id, plano) VALUES ($1, $2) RETURNING id',
      [req.utilizador.id, plano]
    );
    res.status(201).json({ id: Number(rows[0].id), plano, preco: PRECO_ACESSO[plano] });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível pedir o acesso.' });
  }
});

app.post(
  '/api/acessos/:id/comprovativo',
  exigirSessao,
  (req, res, next) => {
    upload.single('comprovativo')(req, res, (err) => {
      if (err) {
        const msg = err.code === 'LIMIT_FILE_SIZE'
          ? 'O ficheiro é demasiado grande (máx. 5 MB).'
          : 'Não foi possível receber o ficheiro.';
        return res.status(400).json({ erro: msg });
      }
      next();
    });
  },
  async (req, res) => {
    const f = req.file;
    const id = idValido(req.params.id);
    if (!f) return res.status(400).json({ erro: 'Junte o comprovativo (PDF, JPG, PNG ou WEBP).' });
    if (!id) {
      fs.unlink(f.path, () => {});
      return res.status(400).json({ erro: 'Acesso inválido.' });
    }
    try {
      const { rows: ant } = await pool.query(
        'SELECT comprovativo_caminho FROM acessos WHERE id = $1 AND utilizador_id = $2 AND pago = false',
        [id, req.utilizador.id]
      );
      if (!ant[0]) {
        fs.unlink(f.path, () => {});
        return res.status(404).json({ erro: 'Acesso pendente não encontrado.' });
      }
      await pool.query('UPDATE acessos SET comprovativo_caminho = $1 WHERE id = $2', [f.filename, id]);
      if (ant[0].comprovativo_caminho) fs.unlink(caminhoDoc(ant[0].comprovativo_caminho), () => {});
      res.json({ ok: true });
    } catch (e) {
      fs.unlink(f.path, () => {});
      console.error(e.message);
      res.status(500).json({ erro: 'Não foi possível enviar o comprovativo.' });
    }
  }
);

app.get('/api/admin/acessos/:id/comprovativo', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Acesso inválido.' });
  try {
    const { rows } = await pool.query('SELECT comprovativo_caminho FROM acessos WHERE id = $1', [id]);
    if (!rows[0] || !rows[0].comprovativo_caminho)
      return res.status(404).json({ erro: 'Comprovativo não encontrado.' });
    res.set('X-Content-Type-Options', 'nosniff');
    res.sendFile(caminhoDoc(rows[0].comprovativo_caminho), (err) => {
      if (err && !res.headersSent) res.status(404).json({ erro: 'Comprovativo não encontrado.' });
    });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível abrir o comprovativo.' });
  }
});

app.get('/api/admin/acessos', exigirAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT a.id, a.plano, a.criado_em, u.nome AS nome, u.email AS email,
              (a.comprovativo_caminho IS NOT NULL) AS comprovativo
       FROM acessos a JOIN utilizadores u ON u.id = a.utilizador_id
       WHERE a.pago = false ORDER BY a.criado_em DESC LIMIT 200`
    );
    res.json(rows.map((r) => ({ ...r, id: Number(r.id), preco: PRECO_ACESSO[r.plano] })));
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível carregar os acessos.' });
  }
});

app.post('/api/admin/acessos/:id/pago', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Acesso inválido.' });
  try {
    const { rows } = await pool.query(
      `UPDATE acessos SET pago = true, expira_em = now() + ($2 * interval '1 day')
       WHERE id = $1 AND pago = false AND comprovativo_caminho IS NOT NULL RETURNING id`,
      [id, DIAS_ACESSO]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Acesso pendente com comprovativo não encontrado.' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível confirmar o pagamento.' });
  }
});

app.post('/api/admin/acessos/:id/remover', exigirAdmin, async (req, res) => {
  const id = idValido(req.params.id);
  if (!id) return res.status(400).json({ erro: 'Acesso inválido.' });
  try {
    const { rows } = await pool.query(
      'DELETE FROM acessos WHERE id = $1 AND pago = false RETURNING comprovativo_caminho',
      [id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Acesso pendente não encontrado.' });
    if (rows[0].comprovativo_caminho) fs.unlink(caminhoDoc(rows[0].comprovativo_caminho), () => {});
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ erro: 'Não foi possível rejeitar.' });
  }
});

/* ---------- Arranque ---------- */
const PORT = process.env.PORT || 3000;

/* Migração automática: cria a coluna "anunciante" se ainda não existir.
   Anúncios antigos ficam como 'proprietario'. */
async function migrar() {
  await pool.query(
    "ALTER TABLE anuncios ADD COLUMN IF NOT EXISTS anunciante text NOT NULL DEFAULT 'proprietario'"
  );
}

migrar()
  .then(() => {
    app.listen(PORT, () => console.log(`Servidor em http://localhost:${PORT}`));
  })
  .catch((e) => {
    console.error('Falha na migração da base de dados:', e.message);
    process.exit(1);
  });
