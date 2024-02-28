import mongoose from 'mongoose';

const FoodSchema=new mongoose.Schema({
    id:String,
    FoodTitle:String,
    FoodContent:String,
    authorId:String,
    subscribedUserId:String,
    activeSubscriber:Boolean 
    })
    
    const userSchema = new mongoose.Schema({
      _id: mongoose.Schema.Types.ObjectId,
      email: String,
      password: String,
      googleId: String,
      role: { type: String, enum: ['user', 'specialUser'], default: 'user' },
    });

    const Blog=mongoose.model('Blog', blogSchema);
    const User = mongoose.model('User', userSchema);

    module.exports = Blog;