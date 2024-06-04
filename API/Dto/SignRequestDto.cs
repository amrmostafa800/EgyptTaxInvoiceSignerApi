namespace API.Dto
{
#nullable disable
    public class SignRequestDto
    {
        public string Document { get; set; }
        public string TokenCertificate { get; set; }
        public string Password { get; set; }
    }
}
