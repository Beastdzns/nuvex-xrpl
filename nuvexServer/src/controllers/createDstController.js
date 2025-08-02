const { createDst } = require('../services/escrowService');
module.exports = async (req, res) => {
  try { res.json(await createDst(req.body)); }
  catch (e) { res.status(500).json({ error: e.message }); }
};