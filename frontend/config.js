/* LAX OSINT — إعدادات البيئة للواجهة الأمامية
   ============================================
   API_URL — رابط الباك إند:
     · محليًا:    "http://127.0.0.1:8000"
     · بعد النشر: "https://lax-osint-production.up.railway.app" (غيّره فور الرفع)

   SUPABASE_URL / SUPABASE_ANON_KEY — من Supabase Dashboard → Settings → API.
   (المفتاح anon علني وآمن على الواجهة؛ الـ service_role محصور في الباك إند فقط)
*/
window.LAX_CONFIG = {
  API_URL: "http://127.0.0.1:8000",
  SUPABASE_URL: "https://jfcfazdzlxgghnqdxiaw.supabase.co",
  SUPABASE_ANON_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImpmY2ZhemR6bHhnZ2hucWR4aWF3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg5NDQ0NDcsImV4cCI6MjEwNDUyMDQ0N30.d-mtWfBvxE6VtKP9hmIosZCoMo0h8Gs-7pzcM-D1SHo"
};