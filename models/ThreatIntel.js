import mongoose from 'mongoose';

const threatIntelSchema = new mongoose.Schema({
  keyword: { type: String, required: true },
  riskWeight: { type: Number, default: 1 },
  reportCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

threatIntelSchema.index({ keyword: 1 }, { unique: true });

const ThreatIntel = mongoose.model('ThreatIntel', threatIntelSchema);
export default ThreatIntel;
