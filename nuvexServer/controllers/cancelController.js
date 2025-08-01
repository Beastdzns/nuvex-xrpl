const { cancel } = require('../services/escrowService');
module.exports = async (req, res) => {
  try { res.json(await cancel(req.params.escrowId, req.body.callerAddress)); }
  catch (e) { res.status(500).json({ error: e.message }); }
};