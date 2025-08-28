const validate = (schema) => async (req, res, next) => {
    try {
        req.body = await schema.parseAsync(req.body);
        next();
    } catch (err) {
        next(err);
    }
};
module.exports = validate;