package usecase

/**
* usecaseはrepositoryのインターフェースのみに依存する
 */

import (
	"go-rest-api/model"
	"go-rest-api/repository"
	"go-rest-api/validator"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type IUserUsecase interface {
	SignUp(user model.User) (model.UserResponse, error)
	Login(user model.User) (string, error) // stringはJWTの想定
}

type userUsecase struct {
	ur repository.IUserRepository
	uv validator.IUserValidator
}

// コンストラクタ リポジトリをDIする
func NewUserUsecase(ur repository.IUserRepository, uv validator.IUserValidator) IUserUsecase {
	return &userUsecase{ur, uv}
}

// ポインタレシーバ インターフェースのメソッドの実装
func (uu *userUsecase) SignUp(user model.User) (model.UserResponse, error) {
	if err := uu.uv.UserValidate(user); err != nil {
		return model.UserResponse{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		return model.UserResponse{}, err
	}
	newUser := model.User{Email: user.Email, Password: string(hash)}
	if err := uu.ur.CreateUser(&newUser); err != nil {
		return model.UserResponse{}, err
	}
	// 返り値のオブジェクトを生成（レスポンスにも型をつけるの厳密ですね）
	resUser := model.UserResponse{
		ID:    newUser.ID,
		Email: newUser.Email,
	}
	// ここまで来る時点でエラーはないのでnilを返す
	return resUser, nil
}

// ポインタレシーバ インターフェースのメソッドの実装
// 引数userは、画面入力値からモデルを作成して渡される想定？
func (uu *userUsecase) Login(user model.User) (string, error) {
	if err := uu.uv.UserValidate(user); err != nil {
		return "", err
	}
	storedUser := model.User{}
	// メールアドレスでユーザーを取得する ポインタ型を渡してるので中でセットされる。
	// 取得したユーザーでどう扱うか、を決めるのはユースケース
	if err := uu.ur.GetUserByEmail(&storedUser, user.Email); err != nil {
		return "", err
	}
	// ユーザー入力されたパスワードと、DBに保存されているパスワードを検証
	err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
	if err != nil {
		return "", err
	}
	// jwtのclaimsを設定（?）
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": storedUser.ID,
		"exp":     time.Now().Add(time.Hour * 12).Unix(),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", nil
	}
	return tokenString, nil
}
