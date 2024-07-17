const bcrypt = require("bcrypt");

const password = "password123";

async function run() {
    const p1 = bcrypt.hash(password, 10);
    const p2 = bcrypt.hash(password, 10);
    const p3 = bcrypt.hash(password, 10);

    const [hashed1, hashed2, hashed3] = await Promise.all([p1, p2, p3]);

    console.log(hashed1);
    console.log(hashed2);
    console.log(hashed3);

    const isMatch = await bcrypt.compare("password123", hashed1);
    const isMatch2 = await bcrypt.compare("password1234", hashed1);
    console.log("Password matches:", isMatch);
    console.log("Password matches:", isMatch2);
}

run();
