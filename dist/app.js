"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
if (process.env.NODE_ENV !== 'production') {
    dotenv_1.default.config();
}
const logger_1 = __importStar(require("./logger"));
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const path_1 = __importDefault(require("path"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const db_index_1 = require("./db/db.index");
/* -------------------------------------------------------------------------- */
/*                             Initialization app                             */
/* -------------------------------------------------------------------------- */
const app = express_1.default();
const logger = logger_1.default.getConsoleLogger("app", logger_1.LOGGING_LEVEL.SILLY);
/* ------------------------------- middlewares ------------------------------ */
app.use(body_parser_1.default.urlencoded({ extended: false }));
app.use(body_parser_1.default.json());
app.use(cookie_parser_1.default());
// app.use(express.static(path.join(__dirname, '../static')))
app.set('view engine', 'pug');
app.set('views', path_1.default.join(__dirname, "../views"));
/* -------------------------------- Constant -------------------------------- */
const JWT_SECRET = "my-secret";
/* -------------------------------------------------------------------------- */
/*                           End initialization app                           */
/* -------------------------------------------------------------------------- */
/* ---------------------------- custom middleware --------------------------- */
function validateJWT(req, res, next) {
    if (!req.cookies.JWT_TOKEN) {
        logger.warn('No JWT token is provided');
        return next();
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(req.cookies.JWT_TOKEN, JWT_SECRET);
        req.user = decoded;
    }
    catch (err) {
        logger.info("JTW error - %s", err.message);
    }
    next();
}
/* ------------------------------- index route ------------------------------ */
app.get('/', validateJWT, (req, res) => {
    logger.debug('user - %o', req.user);
    res.render('index', req.user ? { user: req.user } : {});
});
/* ----------------------------- register route ----------------------------- */
app.get('/register', (req, res) => {
    res.render('register');
});
app.post('/register', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password } = req.body;
    const query = {
        text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
        values: [email]
    };
    const result = yield db_index_1.db.query(query);
    if (result.rowCount > 0) {
        return res.render('register', { message: 'email is not available' });
    }
    const insertQuery = {
        text: `INSERT INTO public.jwt_auth(username, password, role)
      values($1, $2, 'admin')`,
        values: [email, bcryptjs_1.default.hashSync(password)]
    };
    const insertResult = yield db_index_1.db.query(insertQuery);
    res.send({ success: true, message: `Register ${email} successfully` });
}));
/* ------------------------------- login route ------------------------------ */
app.get('/login', (req, res) => {
    res.render('index');
});
app.post('/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    // empty email or password
    if (!username || !password) {
        return res.send({ success: false, message: "email or password is empty" });
    }
    const query = {
        text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
        values: [username]
    };
    const result = yield db_index_1.db.query(query);
    // not found user
    if (result.rowCount === 0) {
        return res.send({ success: false, message: `You are unable to login using ${username}` });
    }
    // wrong password
    if (!bcryptjs_1.default.compareSync(password, result.rows[0].password)) {
        return res.send({ success: false, message: "Incorrect password" });
    }
    // generate tokens
    const user = { username: result.rows[0].username };
    const accessToken = jsonwebtoken_1.default.sign(user, process.env.JWT_ACCESS_TOKEN_SECRET, { expiresIn: '30s', });
    const refreshToken = jsonwebtoken_1.default.sign(user, process.env.JWT_REFRESH_TOKEN_SECRET);
    // update token
    const updateQuery = {
        text: `UPDATE public.jwt_auth SET token = $2 WHERE username = $1`,
        values: [username, refreshToken]
    };
    res.send({ success: true, data: { accessToken, refreshToken } });
    yield db_index_1.db.query(updateQuery);
}));
/* ------------------------------ /token route ------------------------------ */
app.post('/token', (req, res) => {
    const refreshToken = req.body.refreshToken;
    if (!refreshToken) {
        return res.sendStatus(401);
    }
    try {
        const decodedUser = jsonwebtoken_1.default.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET);
        const accessToken = jsonwebtoken_1.default.sign(decodedUser, process.env.JWT_ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
        res.send({ success: true, data: { accessToken } });
    }
    catch (e) {
        logger.error('Invalid token: %s', e.message);
    }
});
/* ------------------------------ logout route ------------------------------ */
app.post('/logout', (req, res) => {
    const refreshToken = req.body.refreshToken;
    if (!refreshToken) {
        return res.sendStatus(401);
    }
    try {
        const decodedUser = jsonwebtoken_1.default.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET);
        res.send({ success: true, message: `${decodedUser.username} is logged out` });
    }
    catch (e) {
        logger.error('Invalid token: %s', e.message);
        res.send({
            success: false, message: `Invalid token `
        });
    }
});
/* -------------------------------------------------------------------------- */
/*                                Server Start                                */
/* -------------------------------------------------------------------------- */
app.listen(6009, () => {
    console.log("Server running at 6009");
});
//# sourceMappingURL=app.js.map