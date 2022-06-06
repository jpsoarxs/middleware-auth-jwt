export default class Middleware {
    constructor({ type = 'Bearer', secret }) {
        this.type = type;
        this.secret = secret;
    }

    middleware(req, res, next) {
        return async (req, res, next) => {
            const { authorization } = req.headers;

            if (!authorization) {
                return res.status(401).json({
                    error: 'No token provided'
                });
            }

            const [tokenType, token] = authorization.split(' ');

            if (tokenType !== this.type) {
                return res.status(401).json({
                    error: 'Invalid token type'
                });
            }

            try {
                const decoded = await jwt.verify(token, this.secret);
                req.user = decoded;
                next();
            } catch (err) {
                if (err.name === 'TokenExpiredError') {
                    return res.status(401).json({
                        error: 'Token expired'
                    });
                }

                return res.status(401).json({
                    error: 'Invalid token'
                });
            }
        };
    }
}