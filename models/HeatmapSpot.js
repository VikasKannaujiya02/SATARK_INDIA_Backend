import mongoose from 'mongoose';

const heatmapSpotSchema = new mongoose.Schema({
  lat: { type: Number, required: true },
  lng: { type: Number, required: true },
  label: { type: String, default: '' },
  riskLevel: { type: String, enum: ['high', 'medium', 'low'], default: 'medium' },
  reportCount: { type: Number, default: 1 },
  createdAt: { type: Date, default: Date.now },
});

const HeatmapSpot = mongoose.model('HeatmapSpot', heatmapSpotSchema);
export default HeatmapSpot;
