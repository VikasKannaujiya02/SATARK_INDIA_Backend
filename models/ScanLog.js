import mongoose from 'mongoose';

const scanLogSchema = new mongoose.Schema({
  type: { type: String, enum: ['url', 'sms'], required: true },
  content: { type: String, required: true },
  riskScore: { type: Number, default: 0 },
  isThreat: { type: Boolean, default: false },
  message: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const ScanLog = mongoose.model('ScanLog', scanLogSchema);
export default ScanLog;
