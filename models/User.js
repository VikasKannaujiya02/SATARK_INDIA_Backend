import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phoneNumber: { type: String, required: true, unique: true },
  avatar: { type: String, default: "" },
  trustScore: { type: Number, default: 100 },
  reportsFiled: { type: Number, default: 0 },
  currentStreak: { type: Number, default: 0 },
  lastLoginDate: { type: Date },
  kycVerified: { type: Boolean, default: false },
  isKycVerified: { type: Boolean, default: false },
  isInsured: { type: Boolean, default: false },
  settings: {
    darkMode: { type: Boolean, default: true },
    notifications: { type: Boolean, default: true },
    language: { type: String, default: 'en' }
  },
  satarkPoints: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
export default User;