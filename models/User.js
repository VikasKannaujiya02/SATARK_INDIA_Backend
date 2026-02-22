import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phoneNumber: { type: String, required: true, unique: true },
  trustScore: { type: Number, default: 100 },
  reportsFiled: { type: Number, default: 0 },
  currentStreak: { type: Number, default: 0 },
  lastLoginDate: { type: Date },
  kycVerified: { type: Boolean, default: false },
  satarkPoints: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
export default User;