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
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const db_index_1 = require("./db/db.index");
const HttpError_1 = require("./types/HttpError");
/* -------------------------------------------------------------------------- */
/*                             Initialization app                             */
/* -------------------------------------------------------------------------- */
const app = express_1.default();
const logger = logger_1.default.getConsoleLogger("app", logger_1.LOGGING_LEVEL.SILLY);
/* ------------------------------- middlewares ------------------------------ */
app.use(body_parser_1.default.urlencoded({ extended: false }));
app.use(body_parser_1.default.json());
app.use(cookie_parser_1.default());
/* -------------------------------------------------------------------------- */
/*                           End initialization app                           */
/* -------------------------------------------------------------------------- */
/* ---------------------------- custom middleware --------------------------- */
function validateRefreshToken(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        const refreshToken = req.body.refreshToken;
        if (!refreshToken) {
            throw new HttpError_1.HttpError(401, "No refresh token is provided");
        }
        // decode user from req.body
        const decodedUser = jsonwebtoken_1.default.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET);
        const query = {
            text: `SELECT token FROM public.jwt_auth WHERE username = $1`,
            values: [decodedUser.username]
        };
        const result = yield db_index_1.db.query(query);
        if (result.rowCount === 0) {
            throw new HttpError_1.HttpError(401, 'user does not exist');
        }
        else if (result.rows[0].token !== refreshToken) {
            throw new HttpError_1.HttpError(404, 'invalid refresh token');
        }
        // set user
        req.user = decodedUser;
        next();
    });
}
/* ------------------------------- index route ------------------------------ */
app.get('/', (req, res) => {
});
/* ----------------------------- register route ----------------------------- */
app.post('/register', (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password } = req.body;
    const query = {
        text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
        values: [email]
    };
    const result = yield db_index_1.db.query(query);
    if (result.rowCount > 0) {
        throw new HttpError_1.HttpError(409, "email is not available");
    }
    const insertQuery = {
        text: `INSERT INTO public.jwt_auth(username, password, role)
      values($1, $2, 'admin')`,
        values: [email, bcryptjs_1.default.hashSync(password)]
    };
    const insertResult = yield db_index_1.db.query(insertQuery);
    // set successful message
    res.message = `Register ${email} successfully`;
    next();
}));
/* ------------------------------- login route ------------------------------ */
app.post('/login', (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    // empty email or password
    if (!username || !password) {
        throw new HttpError_1.HttpError(301, "email or password is empty");
    }
    const query = {
        text: `SELECT * FROM public.jwt_auth WHERE username = $1`,
        values: [username]
    };
    const result = yield db_index_1.db.query(query);
    // not found user
    if (result.rowCount === 0) {
        throw new HttpError_1.HttpError(301, `No user exists: ${username}`);
    }
    // wrong password
    else if (!bcryptjs_1.default.compareSync(password, result.rows[0].password)) {
        throw new HttpError_1.HttpError(301, `Incorrect Password`);
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
    // set payload
    res.data = { accessToken, refreshToken };
    yield db_index_1.db.query(updateQuery);
    next();
}));
/* ------------------------------ /token route ------------------------------ */
app.post('/token', validateRefreshToken, (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    if (req.user) {
        const accessToken = jsonwebtoken_1.default.sign({ username: req.user.username }, process.env.JWT_ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
        res.data = { accessToken };
    }
    next();
}));
/* ------------------------------ logout route ------------------------------ */
app.delete('/logout', validateRefreshToken, (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    if (req.user) {
        res.send({ success: true, message: `${req.user.username} is logged out` });
        // set token to null
        const updateQuery = {
            text: `UPDATE public.jwt_auth SET token = $2 WHERE username = $1`,
            values: [req.user.username, null]
        };
        yield db_index_1.db.query(updateQuery);
        res.message = `Logout ${req.user.username} successfully!`;
    }
    next();
}));
/* ------------------------------- GET /posts ------------------------------- */
const posts = [
    {
        username: 'gjuoun',
        postId: '1'
    },
    {
        username: 'jun',
        postId: '2'
    }
];
app.get('/posts', (req, res, next) => {
    var _a;
    const accessToken = (_a = req.headers.authorization) === null || _a === void 0 ? void 0 : _a.replace('Bearer ', '');
    if (!accessToken) {
        throw new HttpError_1.HttpError(403, "No access token is provided");
    }
    try {
        const decodedUser = jsonwebtoken_1.default.verify(accessToken, process.env.JWT_ACCESS_TOKEN_SECRET);
        res.data = { posts };
        next();
    }
    catch (e) {
        throw new HttpError_1.HttpError(401, "Invalid access token");
    }
});
/* ------------------------------ data handling ----------------------------- */
app.use((err, req, res, next) => {
    if (res.data || res.message) {
        res.send({
            success: true,
            data: res.data,
            message: res.message
        });
    }
    next();
});
/* ----------------------------- error handling ----------------------------- */
app.use(function (err, req, res, next) {
    if (err instanceof HttpError_1.HttpError) {
        res.status(err.status).send({
            success: false,
            message: err.message
        });
    }
    else {
        res.status(500).send({
            success: false,
            message: err.message
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