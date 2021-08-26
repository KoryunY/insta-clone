const express = require("express");
const bodyParser = require("body-parser");
const multer = require("multer");
const fs = require("fs");
const { v4: uuid4 } = require("uuid");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const jwtDecode = require("jwt-decode");
const saltRounds = 10;

const app = express();

const dataPath = "./db/fakedb.json";

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use(multer({ dest: "uploads" }).single("filedata"));

const getData = () => {
    let data = fs.readFileSync(dataPath);
    return JSON.parse(data);
}

const saveData = (data) => {
    let stringifyData = JSON.stringify(data);
    fs.writeFileSync(dataPath, stringifyData);
}

const registerValidation = (data, username, email) => {
    return data['users'].find(element => {
        if (element.email == email || element.username == username) {
            return element;
        }
    }) == null;
}

const findById = (data, username) => {
    return data['users'].find(element => {
        if (element.username == username) {
            return element;
        }
    })
}

const isTokenActive = (token) => {
    let decode = jwtDecode(token);
    return Date.now() / 1000 < decode.exp;
}

app.post('/users/register', (req, res) => {
    let data = getData();
    let id = uuid4();
    let password = req.body.password;
    let username = req.body.username;
    let email = req.body.email;
    if (password.length > 6 && registerValidation(data, username, email)) {
        bcrypt.genSalt(saltRounds, function (err, salt) {
            bcrypt.hash(password, salt, function (err, hash) {
                if (!err) {
                    let obj = {
                        "id": id,
                        "username": username,
                        "email": email,
                        "password": hash,
                        "token": ""
                    }
                    data['users'].push(obj);
                    saveData(data);
                    res.send("Okk!!");
                }
                else {
                    res.sendStatus(401);
                }
            });
        });
    }
    else {
        res.send("Validation error");
    }
});

app.post("/users/login", (req, res) => {
    let data = getData();

    let emails = data['users'].map((element) => {
        return element.email;
    })

    let obj = data['users'].find(element => {
        if (element.email == req.body.email) {
            return element;
        }
    })

    let index = data['users'].indexOf(obj);
    let email = req.body.email;
    if (emails.includes(email)) {

        bcrypt.compare(req.body.password, obj.password, function (err, result) {
            if (result) {
                let token = jwt.sign(
                    { id: data['users'][index].id, email: email },
                    "secret",
                    {
                        expiresIn: "2h",
                    }
                );
                data['users'][index]['token'] = token;
                saveData(data);
                res.send("ok");
            }
            else {
                res.send("invalid pass");
            }
        });
    }
    else {
        res.send("invalid email");
    }
})

app.post("/users/upload", (req, res) => {
    let data = getData();
    let username = req.body.username;
    let file = req.file;
    let title = req.body.title;
    if (file && username) {
        let fileType = file.mimetype.split('/').pop();
        let user = findById(data, username);
        if ((fileType == 'jpg' || fileType == 'png' || fileType == 'jpeg' || fileType == 'gif')
            && isTokenActive(user.token)) {
            let obj = {
                "id": user.id,
                "title": title,
                "path": file.path
            }
            data['photos'].push(obj);
            saveData(data);
            res.send("Image successfully uploaded to the server.")
        }
        else {
            fs.unlinkSync(file.path);
            res.send('Invalid filetype or user Token expired');
        }
    }
    else {
        res.send("error");
    }
})


app.listen(8080, () => {
    console.log("server start!");
})