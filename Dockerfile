# Use the official Node.js image from the Docker Hub
FROM node:16

# Create and change to the app directory
WORKDIR /usr/src/app

# Copy application dependency manifests to the container image.
COPY package*.json ./

# Install production dependencies.
RUN npm install --only=production

# Copy local code to the container image.
COPY . .

# Inform Docker that the container listens on port 8080.
EXPOSE 8080

# Run the web service on container startup.
CMD [ "node", "app.js" ]
