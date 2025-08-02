const { fund } = require('../services/escrowService');
module.exports = async (req, res) => {
  try { res.json(await fund(req.params.escrowId, req.body.txHash)); }
  catch (e) { res.status(500).json({ error: e.message }); }
};