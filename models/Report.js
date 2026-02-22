import mongoose from 'mongoose';

const reportSchema = new mongoose.Schema({
  scammerNumber: { type: String, required: true },
  platform: { type: String, default: 'unknown' },
  description: { type: String, default: '' },
  status: { type: String, default: 'pending' },
  reportedBy: { type: String },
  trackingId: { type: String },
  reportCount: { type: Number, default: 1 },
  createdAt: { type: Date, default: Date.now },
});

const Report = mongoose.model('Report', reportSchema);
export default Report;
