import mongoose from 'mongoose';

const contactSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  relation: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const Contact = mongoose.model('Contact', contactSchema);
export default Contact;
