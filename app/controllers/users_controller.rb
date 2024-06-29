class UsersController < ApplicationController
    include ActionController::Cookies

    def register
        salt = Rails.application.credentials.password_salt
        u_params = user_params
        u_params[:password_digest] = BCrypt::Engine.hash_secret(u_params[:password], salt)
        u_params.delete(:password)
        user=User.create(u_params)
        if !user.errors.size
            render json: { message: "A user record for #{user_params["name"]} was created."}, status: 201
        else
            render json: { message: "Creation of the user record failed. " + user.errors.full_messages.join(". ") }
        end
    end

    def logon
        salt = Rails.application.credentials.password_salt
        password_hash = BCrypt::Engine.hash_secret(logon_params[:password], salt)
        users = User.where("email = '#{logon_params[:email]}' AND password_digest = '#{password_hash}'")
        if users.length == 0
            render json: { message: "Authentication failed."}, status: 401
        else
            @user = users[0]
            hmac_secret = Rails.application.credentials.secret_key_base
            payload = { id: @user.id }
            token = JWT.encode payload, hmac_secret, 'HS256'
            if ENV["INSECURE_COOKIES"] == "true"
                secure_cookie = false
            else
                secure_cookie = true
            end
            cookies["JWT"] = { value: token, same_site: :None, secure: secure_cookie, partitioned: true, httponly: true }
            if !@user.phrase
                @user.phrase = ""
            end
            render json: { user: {name: @user.name, phrase: @user.phrase}}, status: 201
        end
    end

    def setphrase
        if !is_user_logged_in?
            return
        end
        if (!phrase_params["phrase"])
            phrase_params.phrase = ""
        end
        @user.update(phrase: phrase_params["phrase"])
        render json: { message: "The phrase was updated.",
                           user: { name: @user.name, phrase: phrase_params["phrase"]}}, status: 200
    end

    def getuser
        if !is_user_logged_in?
            return
        end
        render json: { user: {name: @user.name, phrase: @user.phrase}}, status: 200
    end

    def logoff
        cookies.delete "JWT"
        render json: { message: "You have logged off."}, status: 200
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

    def is_user_logged_in?
        if !cookies["JWT"]
            render json: { message: "No user is authenticated"}, status: 401
            return false
        else
            hmac_secret = Rails.application.credentials.secret_key_base
            begin
                decoded_token = JWT.decode cookies["JWT"], hmac_secret, {algorithm: 'HS256'}
            rescue
                render json: { message: "Invalid JWT provided."}, status: 401
                return false
            end
            puts(decoded_token)
            @user = User.find(decoded_token[0]["id"].to_s)
            if (!@user)
                render json: { message: "Invalid user specified."}, status: 401
                return false
            end
        end
        return true
    end

end
