class User < ApplicationRecord
  attr_accessor :remember_token

  validates :name,  presence: true, length: { maximum:  50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 255 },
                    format: { with: VALID_EMAIL_REGEX },
                    uniqueness: { case_sensitive: false }
  has_secure_password
  validates :password, presence: true, 
    length: { minimum: 6 }, allow_nil: true

  #渡された文字列のハッシュを返すよ
  #パスワードを入力すると暗号化された文字列を生成してくれる。
  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

  #ランダムなトークンを返すよ
  def User.new_token
    SecureRandom.urlsafe_base64
  end

  #一度remember_tokenという奴に代入、remember_tokenはattr_accessorでUserモデルと #紐づいて定義されている。selfは今のユーザー #そのユーザーのremember_digestカラムの中にremember_tokenをdigestにしたものを入れて上書き

  def remember
    self.remember_token = User.new_token
    self.update_attribute(:remember_digest, User.digest(remember_token))
  end
  
  def forget
    self.update_attribute(:remember_digest, nil)
  end
  
  # 渡されたトークンがダイジェストと一致したらtrueを返す
  def authenticated?(remember_token)
    return false if remember_digest.nil?
    BCrypt::Password.new(self.remember_digest).is_password?(remember_token)
  end
end
