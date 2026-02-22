import mongoose from 'mongoose';

// userId/userPhone: String or ObjectId - use phone for GET /api/family/:phone
const familySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.Mixed,
    required: true,
  },
  userPhone: { type: String },
  name: {
    type: String,
    required: true,
  },
  relation: {
    type: String,
    required: true,
  },
  phoneNumber: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Family = mongoose.model('Family', familySchema);
export default Family;
