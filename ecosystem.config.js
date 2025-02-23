module.exports = {
  apps: [
    {
      name: "backend-app",            
      script: "index.js",           
      env: {
        NODE_ENV: "development",       // متغیر NODE_ENV برای حالت تولید
        DATABASE_URL: process.env.DATABASE_URL,
        BASE_URL: process.env.BASE_URL,
        FRONT_PORT: process.env.FRONT_PORT,
      },
    },
  ],
};
