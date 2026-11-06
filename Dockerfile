FROM node:24
LABEL maintainer "William Hilton <wmhilton@gmail.com>"
WORKDIR /srv
COPY . .
RUN npm ci
EXPOSE 9999
ENV PORT=9999
CMD [ "npm", "start" ]
