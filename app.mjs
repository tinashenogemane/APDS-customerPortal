import express from "express";
const app = express();

app.get('/',(req,res)=>{
    res.send('HTTPS in ExpressJS')
})

export default app;