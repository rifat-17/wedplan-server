import { MongoClient } from 'mongodb';
import 'dotenv/config';
import express from 'express';
import cors from 'cors';

const app = express();

const port = process.env.PORT || 5001;

//middleware
app.use(express.json());
app.use(cors());




const client = new MongoClient(process.env.MONGODB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}



app.get('/', (req, res) => {
  res.send('Wedding is loadingggg!')
})

app.listen(port, () => {
  console.log(`Wedding is loading at ${port}`)
})