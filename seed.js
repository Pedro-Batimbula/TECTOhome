require('dotenv').config();
const pool = require('./db');

const IMG = (id) => `https://images.unsplash.com/${id}?w=800&q=80&auto=format&fit=crop`;

const FOTOS = {
  terreno1: 'photo-1683348268445-1695508fb8c5',
  terreno2: 'photo-1646529514110-62c11d1304ac',
  terreno3: 'photo-1729342362987-f9a04e5ff914',
  apart1: 'photo-1760894492960-5b0a2da0676d',
  apart2: 'photo-1768164630015-1ad8a3a574fe',
  apart3: 'photo-1766321258844-6541b34b2940',
  armazem1: 'photo-1669003750652-2027bd69e7a1',
  armazem2: 'photo-1674252247615-210f04462fd2',
};

const ANUNCIOS = [
  /* ---------- Terrenos ---------- */
  { categoria: 'terreno', tipo: 'venda', titulo: 'Terreno vedado de 600 m² com documentos em dia',
    prov: 'Luanda', mun: 'Cacuaco', bairro: 'Kikolo', preco: 18000000, area: 600,
    tel: '923200101', img: 'terreno1', pub: 2, dias: 28, plano: 'basico',
    desc: 'Terreno plano e vedado, com árvores à volta e acesso por estrada. Documentos regularizados, pronto para construir.' },
  { categoria: 'terreno', tipo: 'venda', titulo: 'Terreno de 1.000 m² para construção',
    prov: 'Benguela', mun: 'Catumbela', bairro: 'Biópio', preco: 25000000, area: 1000,
    tel: '924200202', img: 'terreno2', pub: 5, dias: 25, plano: 'basico',
    desc: 'Terreno amplo e limpo, com árvores ao fundo, perto da estrada principal. Serve para moradia, armazém ou condomínio.' },
  { categoria: 'terreno', tipo: 'venda', titulo: 'Terreno de 800 m² junto a estrada de terra batida',
    prov: 'Huambo', mun: 'Huambo', bairro: 'Santo António', preco: 14000000, area: 800,
    tel: '925200303', img: 'terreno3', pub: 8, dias: 22, plano: 'basico',
    desc: 'Terreno verde e plano, com acesso por caminho de terra batida. Zona calma e a crescer, com água e luz por perto.' },

  /* ---------- Apartamentos ---------- */
  { categoria: 'apartamento', tipo: 'arrendamento', titulo: 'Apartamento T2 com varanda no Talatona',
    prov: 'Luanda', mun: 'Talatona', bairro: 'Cidade Financeira', preco: 650000,
    quartos: 2, banhos: 2, area: 98, salas: 1, cozinhas: 1, varandas: 1, quintal: false,
    tel: '926200404', img: 'apart1', pub: 3, dias: 27, plano: 'medio',
    desc: 'Apartamento novo com varanda, cozinha equipada e estacionamento. Prédio com segurança e gerador.' },
  { categoria: 'apartamento', tipo: 'venda', titulo: 'Apartamento T3 moderno com duas varandas',
    prov: 'Luanda', mun: 'Ingombota', bairro: 'Marginal', preco: 72000000,
    quartos: 3, banhos: 2, area: 135, salas: 2, cozinhas: 1, varandas: 2, quintal: false,
    tel: '927200505', img: 'apart2', pub: 6, dias: 24, plano: 'premium',
    desc: 'Apartamento moderno com varandas de vidro, duas salas e cozinha ampla. Prédio com elevador e estacionamento.' },
  { categoria: 'apartamento', tipo: 'arrendamento', titulo: 'Apartamento T1 novo no centro do Lubango',
    prov: 'Huíla', mun: 'Lubango', bairro: 'Centro', preco: 260000,
    quartos: 1, banhos: 1, area: 62, salas: 1, cozinhas: 1, varandas: 1, quintal: false,
    tel: '928200606', img: 'apart3', pub: 9, dias: 21, plano: 'basico',
    desc: 'Apartamento novo e luminoso, ideal para uma pessoa ou casal. Perto de escolas, mercado e transportes.' },

  /* ---------- Armazéns ---------- */
  { categoria: 'armazem', tipo: 'arrendamento', titulo: 'Armazém de 800 m² com zona de cargas',
    prov: 'Luanda', mun: 'Viana', bairro: 'Zona Industrial', preco: 1800000, banhos: 2, area: 800,
    tel: '929200707', img: 'armazem1', pub: 4, dias: 26, plano: 'basico',
    desc: 'Armazém em estrutura metálica, com portões de cargas, pátio para camiões e escritório. Zona industrial com boa estrada.' },
  { categoria: 'armazem', tipo: 'venda', titulo: 'Armazém de 450 m² com grande espaço interior livre',
    prov: 'Benguela', mun: 'Benguela', bairro: 'Zona Industrial', preco: 95000000, banhos: 1, area: 450,
    tel: '923200808', img: 'armazem2', pub: 7, dias: 23, plano: 'medio',
    desc: 'Armazém com piso em betão, janelas altas e muita luz natural. Espaço livre e adaptável a stock, oficina ou produção.' },
];

(async () => {
  try {
    const { rows: u } = await pool.query(
      "SELECT id FROM utilizadores ORDER BY (papel = 'admin') DESC, id LIMIT 1"
    );
    if (!u[0]) throw new Error('Não há nenhum utilizador. Cria primeiro a conta (ou o administrador).');

    /* Remove as demonstrações antigas */
    await pool.query(
      "DELETE FROM fotos WHERE anuncio_id IN (SELECT id FROM anuncios WHERE documento_caminho = 'demo')"
    );
    const { rowCount } = await pool.query("DELETE FROM anuncios WHERE documento_caminho = 'demo'");
    console.log('Removidas', rowCount, 'demonstrações antigas.');

    for (const c of ANUNCIOS) {
      const { rows } = await pool.query(
        `INSERT INTO anuncios
           (utilizador_id, tipo, categoria, titulo, descricao, preco, provincia, municipio, bairro,
            quartos, banhos, area_m2, salas, cozinhas, varandas, quintal, contacto, plano,
            documento_caminho, estado, pago, publicado_em, expira_em)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                 'demo','publicado', true,
                 now() - make_interval(days => $19), now() + make_interval(days => $20))
         RETURNING id`,
        [u[0].id, c.tipo, c.categoria, c.titulo, c.desc, c.preco, c.prov, c.mun, c.bairro,
         c.quartos ?? null, c.banhos ?? null, c.area, c.salas ?? null, c.cozinhas ?? null,
         c.varandas ?? null, c.quintal ?? null, c.tel, c.plano, c.pub, c.dias]
      );
      await pool.query(
        'INSERT INTO fotos (anuncio_id, caminho, ordem) VALUES ($1, $2, 0)',
        [rows[0].id, IMG(FOTOS[c.img])]
      );
      console.log('Criado:', c.categoria, '-', c.titulo);
    }
    console.log('Pronto:', ANUNCIOS.length, 'anúncios de demonstração.');
  } catch (e) {
    console.error('Erro:', e.message);
  } finally {
    await pool.end();
  }
})();