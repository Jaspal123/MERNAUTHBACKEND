const express = require("express")
const morgan = require('morgan')
const cors = require('cors')
const chalk = require('chalk')
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
require('dotenv').config()

// App init
const app = express()

// DB Connection
mongoose.connect(process.env.DATABASE, {
    useNewUrlParser: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
    useCreateIndex: true
})
.then(() => console.log(chalk.bgBlue.bold('DB Connected')))
.catch(err => console.log(chalk.bgRed.bold('DB Connection Error'),err))

// Import  Rutes
const authRoutes = require('./routes/auth')

// App middlewares
app.use(morgan('dev'))
app.use(bodyParser.json())
// app.use(cors()) //Allows all origins

if(process.env.NODE_ENV='development'){
    app.use(cors({origin: `http://localhost:3000`}))
}
// middleware
app.use('/api',authRoutes)


const port = process.env.PORT || 8000

app.listen(port, () => console.log(chalk.bgGreen.bold(`App is running on port ${port}`)))