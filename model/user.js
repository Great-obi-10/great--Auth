const mongoose = require('mongoose');

const UserSchema = mongoose.Schema({
    username: {
        type: 'string',
        required: true, 
        unique: true},

    password:{
        type: 'string',
        required: true,
        minlength: 5 }
},
{collection: 'users'}
)  

const model =mongoose.model('UserSchema',UserSchema)

module.exports = model 