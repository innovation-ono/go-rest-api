package validator

import (
	"go-rest-api/model"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type IUserValidator interface {
	UserValidate(user model.User) error
}

type userValidator struct{}

func NewUserValidator() IUserValidator {
	return &userValidator{}
}

func (uv *userValidator) UserValidate(user model.User) error {
	return validation.ValidateStruct(&user,
		validation.Field(
			&user.Email,
			validation.Required.Error("メールアドレスは必須です。"),
			validation.RuneLength(1, 50).Error("メールアドレスは最大50字です。"),
			is.Email.Error("メールアドレスの形式で入力してください。"),
		),
		validation.Field(
			&user.Password,
			validation.Required.Error("パスワードは必須です。"),
			validation.RuneLength(6, 30).Error("パスワードは6〜30文字で入力してください。"),
		),
	)
}
