function handler(req) {
  const q = req.query.q;
  db.query("SELECT * FROM t WHERE k = " + q);
}
