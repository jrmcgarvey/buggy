class User < ApplicationRecord
    has_secure_password
    validates :name, presence: true, format: { with: 
    /\A[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])?[a-zA-Z]*)*\z/ , message: "Please enter a valid name" }
    validates :email, presence: true, uniqueness: true, format: { 
        with: /\A[A-Za-z0-9+_.-]+@([A-Za-z0-9]+\.)+[A-Za-z]{2,6}\z/ , message: "Please enter a valid email address"}
    validates :password, password_strength: true
    before_save :phrase_escape

    private

    def phrase_escape
        self.phrase = Rack::Utils.escape_html(phrase)
        self.email = email.downcase
    end
end
