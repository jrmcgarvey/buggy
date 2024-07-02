class UsersController < ApplicationController
  include ActionController::Cookies
  before_action :user_logged_in, only: %i[setphrase getuser]

  def register
    salt = Rails.application.credentials.password_salt
    u_params = user_params
    u_params[:password_digest] = BCrypt::Engine.hash_secret(u_params[:password], salt)
    u_params.delete(:password)
    user = User.create(u_params)
    if user.errors.empty?
      render json: { message: "A user record for #{user_params['name']} was created." }, status: 201
    else
      render json: { message: "Creation of the user record failed. #{user.errors.full_messages.join('. ')}" },
             status: 400
    end
  end

  def logon
    salt = Rails.application.credentials.password_salt
    password_hash = BCrypt::Engine.hash_secret(logon_params[:password], salt)
    users = User.where("email = '#{logon_params[:email]}' AND password_digest = '#{password_hash}'")
    if users.empty?
      render json: { message: 'Authentication failed.' }, status: 401
    else
      @user = users[0]
      hmac_secret = Rails.application.credentials.secret_key_base
      payload = { id: @user.id }
      token = JWT.encode payload, hmac_secret, 'HS256'
      # ignore the following, as it is a workaround for a Postman problem.
      secure_cookie = (ENV['INSECURE_COOKIES'] != 'true')
      # end of Postman workaround
      cookies['JWT'] =
        { value: token, same_site: :None, secure: secure_cookie, partitioned: true, httponly: true }
      @user.phrase = '' unless @user.phrase
      render json: { user: { name: @user.name, phrase: @user.phrase } }, status: 201
    end
  end

  def setphrase
    phrase_params.phrase = '' unless phrase_params['phrase']
    @user.update(phrase: phrase_params['phrase'])
    render json: { message: 'The phrase was updated.',
                   user: { name: @user.name, phrase: phrase_params['phrase'] } }, status: 200
  end

  def getuser
    render json: { user: { name: @user.name, phrase: @user.phrase } }, status: 200
  end

  def logoff
    cookies.delete 'JWT'
    render json: { message: 'You have logged off.' }, status: 200
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :password)
  end

  def logon_params
    params.require(:user).permit(:email, :password)
  end

  def phrase_params
    params.permit(:phrase)
  end

  def user_logged_in?
    if !cookies['JWT']
      render json: { message: 'No user is authenticated' }, status: 401
      return false
    else
      hmac_secret = Rails.application.credentials.secret_key_base
      begin
        decoded_token = JWT.decode cookies['JWT'], hmac_secret, { algorithm: 'HS256' }
      rescue StandardError
        render json: { message: 'Invalid JWT provided.' }, status: 401
        return false
      end
      puts(decoded_token)
      @user = User.find(decoded_token[0]['id'].to_s)
      unless @user
        render json: { message: 'Invalid user specified.' }, status: 401
        return false
      end
    end
    true
  end
end
