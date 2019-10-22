using System;
using System.Text;
using Business.CLR.MessageProviders.Factories;
using Business.CLR.MessageProviders.Providers.Helpers;
using eBankit.Common.Security.Encryption;
using eBankit.Common.Security.Encryption.Algorithms;
using eBankit.Common.Security.Hash;
using eBankit.Common.Settings;
using eBankit.Middleware.Data.GPM.DataAccess;
using eBankit.Middleware.Data.GPM.DataAccess.Credentials;
using eBankit.Middleware.GPM.BusinessLogic.Factories.Interfaces;
using eBankit.Middleware.GPM.Common.Services;
using Newtonsoft.Json;

namespace Business.CLR.MessageServices.Email
{
    public class EmailCodeAccessManagement : IAccessCodeManagement
    {
        public OutAccessCode Activate(InAccessCode input)
        {
            return new OutAccessCode
            {
                Success = true
            };
        }

        /// <summary>
        /// Deletes the specifies input
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public OutAccessCode Delete(InAccessCode input)
        {
            return new OutAccessCode
            {
                Success = true
            };
        }

        /// <summary>
        /// Locks the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public OutAccessCode Lock(InAccessCode input)
        {
            return new OutAccessCode
            {
                Success = true
            };
        }

        /// <summary>
        /// Registers the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public OutAccessCode Register(InAccessCode input)
        {
            return new OutAccessCode
            {
                Success = true
            };
        }

        /// <summary>
        /// Requests the challenge.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public OutAccessCode RequestChallenge(InAccessCode input)
        {
            try
            {
                var sender = EmailProviderFactory.GetEmailProvider();
                var credentialData = JsonConvert.DeserializeObject<EmailDataWrapper>(input.CredentialData);

                var token = OneTimePassword.GenerateOTP();
                var enc = GetEncriptor(input);
                var encryptToken = enc.EncryptStr(token);

                credentialData.TemplateMessage = credentialData.TemplateMessage.Replace("{99999}", token);
                input.CredentialData = token;

                Update(input);

                var result = sender.SendEmail(credentialData.Email, credentialData.TemplateSubject, credentialData.TemplateMessage);

                if (string.IsNullOrEmpty(result.ErrorCode))
                {
                    return new OutAccessCode
                    {
                        Success = true,
                        CredentialData = JsonConvert.SerializeObject(
                            new
                            {
                                Token = encryptToken,
                                MaxLife = DateTime.Now.AddMinutes(5)
                            })
                    };
                }

                return new OutAccessCode
                {
                    Success = false,
                    Error = new AccessCodeError { ErrorCode = "999999", ErrorMessage = "Unknown Error", SystemErrorMessage = "Unknown Error" }
                };
            }
            catch (Exception e)
            {
                var error = new AccessCodeError { ErrorCode = "999998", ErrorMessage = e.Message, SystemErrorMessage = e.StackTrace };
                return new OutAccessCode
                {
                    Error = error,
                    Success = false
                };
            }
        }

        /// <summary>
        /// Uns the lock.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public OutAccessCode UnLock(InAccessCode input)
        {
            return new OutAccessCode
            {
                Success = true
            };
        }

        /// <summary>
        /// Updates the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public OutAccessCode Update(InAccessCode input)
        {
            try
            {
                if (!string.IsNullOrEmpty(input.CredentialData))
                {
                    var concAccessCode = new StringBuilder();
                    concAccessCode.Append(input.AccessCodeId.ToString());
                    concAccessCode.Append(input.CredentialData);
                    var argonAccessCode = PasswordHash.Hash(concAccessCode.ToString());
                    Authentication.UpdatePassword((short)input.CorporationId, input.AccessCodeId, input.Language,
                        input.ChannelId, argonAccessCode);
                    return new OutAccessCode
                    {
                        Success = true
                    };
                }

                return new OutAccessCode
                {
                    Success = false
                };
            }
            catch (Exception e)
            {
                var error = new AccessCodeError { ErrorCode = "0", ErrorMessage = e.Message, SystemErrorMessage = e.StackTrace };
                return new OutAccessCode
                {
                    Error = error,
                    Success = false
                };
            }
        }

        /// <summary>
        /// Validates the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        public OutAccessCode Validate(InAccessCode input)
        {
            try
            {
                if (!string.IsNullOrEmpty(input.CredentialData))
                {
                    var concAccessCode = new StringBuilder("");
                    concAccessCode.Append(input.AccessCodeId.ToString());
                    concAccessCode.Append(input.CredentialData);
                    var inputContext = new InputContextType
                    {
                        CorporationId = (short)input.CorporationId,
                        ChannelId = input.ChannelId,
                        Language = input.Language
                    };
                    var existingAccessCode =
                        CredentialsMembershipDataAccess.GetAccessCodeValue(inputContext, input.AccessCodeId);
                    if (!PasswordHash.Validate(concAccessCode.ToString(), existingAccessCode))
                    {
                        throw new Exception("Validation failed");
                    }


                    // Clear token from database
                    var argonAccessCode = PasswordHash.Hash(DateTime.Now.Ticks.ToString());
                    Authentication.UpdatePassword((short)input.CorporationId, input.AccessCodeId, input.Language,
                        input.ChannelId, argonAccessCode);

                    return new OutAccessCode
                    {
                        Success = true,
                        ActionFlags = SecurityCenterActionFlags.RestoreFailures
                    };
                }

                return new OutAccessCode
                {
                    Success = false,
                    ActionFlags = SecurityCenterActionFlags.IncrementFailures
                };

            }
            catch (Exception e)
            {
                var error = new AccessCodeError { ErrorCode = "0", ErrorMessage = e.Message, SystemErrorMessage = e.StackTrace };
                return new OutAccessCode
                {
                    Error = error,
                    Success = false,
                    ActionFlags = SecurityCenterActionFlags.IncrementFailures
                };
            }
        }

        /// <summary>
        /// Used to wrap the necessary information to send the email
        /// This class matches up with EmailAuthenticationTokenTransaction, but since its json we don't need to add a new reference to it
        /// </summary>
        private sealed class EmailDataWrapper
        {
            public string Email { get; set; }
            public string TemplateMessage { get; set; }
            public string TemplateSubject { get; set; }
        }

        private AESEncryptor GetEncriptor(InAccessCode input)
        {
            var enc = (AESEncryptor)EncryptionFactory.GetEncryptor("AES");
            enc.Password = Convert.ToBase64String(Encoding.ASCII.GetBytes(AppSettings.GetAppSetting("Security.Encryptor.Password", "ebankIT | Omnichannel Innovation")));
            enc.Salt = input.ExtendedProperty;
            return enc;
        }
    }
}
