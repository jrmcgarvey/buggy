# syntax = docker/dockerfile:1

FROM ruby:3.2.1 AS buggy-corrected

# Set the working directory
WORKDIR /app

# Install gems
COPY Gemfile Gemfile.lock ./
RUN gem install bundler && \
    bundle install --jobs 4

# Copy the application code
COPY . .

# Expose ports
EXPOSE 3000

# Set the entrypoint command
CMD ["./migrate-run.sh"]
