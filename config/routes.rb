Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
  post '/users', to: "users#register"
  post '/users/logon', to: "users#logon"
  get '/user', to: "users#getuser"
  delete '/users/logoff', to: "users#logoff"
  post '/user/update', to: "users#setphrase"
end
