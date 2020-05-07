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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const logger_1 = __importStar(require("./logger"));
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const path_1 = __importDefault(require("path"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importStar(require("jsonwebtoken"));
const moment_1 = __importDefault(require("moment"));
const db_index_1 = require("./db/db.index");
const app = express_1.default();
const logger = logger_1.default.getConsoleLogger("app", logger_1.LOGGING_LEVEL.SILLY);
app.use(body_parser_1.default.urlencoded({ extended: false }));
app.use(body_parser_1.default.json());
app.use(cookie_parser_1.default());
// app.use(express.static(path.join(__dirname, '../static')))
app.set('view engine', 'pug');
app.set('views', path_1.default.join(__dirname, "../views"));
const JWT_SECRET = "my-secret";
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
        if (err instanceof jsonwebtoken_1.JsonWebTokenError) {
            logger.info("JTW error - %s", err.message);
        }
        else if (err instanceof jsonwebtoken_1.NotBeforeError) {
            logger.info('JTW not before err - %s', err.message);
        }
        else if (err instanceof jsonwebtoken_1.TokenExpiredError) {
            logger.info('JWT expired - %s', err.message);
        }
    }
    next();
}
app.get('/', validateJWT, (req, res) => {
    logger.debug('user - %o', req.user);
    res.render('index', req.user ? { user: req.user } : {});
});
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
    // res.send({ success: true, data: `Register ${email} successfully` })
    res.render('register', { message: `Register ${email} successfully` });
}));
app.get('/login', (req, res) => {
    res.render('index');
});
app.post('/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.send({ success: false, message: "email or password is empty" });
    }
    const query = {
        text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
        values: [email]
    };
    const result = yield db_index_1.db.query(query);
    if (result.rowCount === 0) {
        return res.render('index', { message: `You are unable to login using ${email}` });
    }
    const { username } = result.rows[0];
    if (!bcryptjs_1.default.compareSync(password, result.rows[0].password)) {
        return res.render('index', { message: "Incorrect password" });
    }
    // set JWT_TOKEN cookie
    res.cookie(`JWT_TOKEN`, jsonwebtoken_1.default.sign({ username }, JWT_SECRET), {
        expires: moment_1.default().add(7, 'days').toDate(),
        httpOnly: true,
        path: '/',
        sameSite: 'lax'
    });
    res.render('index', { user: { username } });
}));
app.post('/logout', (req, res) => {
    res.redirect('/');
});
app.listen(6009, () => {
    console.log("Server running at 6009");
});
//# sourceMappingURL=app.js.map