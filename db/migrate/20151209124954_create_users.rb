class CreateUsers < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.string :name
      t.string :email
      t.string :encrypted_password
      # t.string :confirmation_token
      # t.string :remember_token

      t.timestamps null: false
    end
  end
end
