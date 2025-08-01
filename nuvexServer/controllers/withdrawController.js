const { withdraw } = require('../services/escrowService');
module.exports = async (req, res) => {
  const { secret, callerAddress, isPublic } = req.body;
  try { res.json(await withdraw(req.params.escrowId, secret, callerAddress, isPublic)); }
  catch (e) { res.status(500).json({ error: e.message }); }
};